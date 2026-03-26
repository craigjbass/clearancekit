//
//  FileAuthPipelineTests.swift
//  clearancekitTests
//

import Testing
import Foundation
import os

// MARK: - FakePipelineProcessTree

private final class FakePipelineProcessTree: @unchecked Sendable, ProcessTreeProtocol {
    var containsResult = false
    var ancestorsResult: [AncestorInfo] = []

    func insert(_ record: ProcessRecord) {}
    func remove(identity: ProcessIdentity) {}

    func contains(identity: ProcessIdentity) -> Bool {
        containsResult
    }

    func ancestors(of identity: ProcessIdentity) -> [AncestorInfo] {
        ancestorsResult
    }

    func allRecords() -> [ProcessRecord] { [] }
}

// MARK: - Helpers

private func identity(pid: pid_t = 100, version: UInt32 = 1) -> ProcessIdentity {
    ProcessIdentity(pid: pid, pidVersion: version)
}

private func fileAuthEvent(
    path: String,
    processPath: String = "/usr/bin/test",
    teamID: String = "",
    signingID: String = "",
    respond: @escaping @Sendable (Bool, Bool) -> Void
) -> FileAuthEvent {
    FileAuthEvent(
        correlationID: UUID(),
        operation: .open,
        path: path,
        processIdentity: identity(),
        processID: 100,
        parentPID: 1,
        processPath: processPath,
        teamID: teamID,
        signingID: signingID,
        uid: 501,
        gid: 20,
        ttyPath: nil,
        deadline: 0,
        respond: respond
    )
}

// MARK: - FileAuthPipelineTests

@Suite("FileAuthPipeline", .serialized)
struct FileAuthPipelineTests {

    @Test("globally allowed event responds on hot path without entering slow queue")
    func globallyAllowedFastPath() {
        let processTree = FakePipelineProcessTree()
        let allowlist = [AllowlistEntry(processPath: "/usr/bin/test")]

        let responded = DispatchSemaphore(value: 0)
        var allowedResult = false
        var cacheResult = false

        let postRespondCalled = DispatchSemaphore(value: 0)

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [] },
            allowlistProvider: { allowlist },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() }
        )
        pipeline.start()

        let event = fileAuthEvent(path: "/any/path") { allowed, cache in
            allowedResult = allowed
            cacheResult = cache
            responded.signal()
        }

        pipeline.submit(event)

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult == true)
        #expect(cacheResult == true)

        let m = pipeline.metrics()
        #expect(m.eventBufferEnqueueCount == 1)
        #expect(m.hotPathProcessedCount == 1)
        #expect(m.hotPathRespondedCount == 1)
        #expect(m.slowQueueEnqueueCount == 0)
    }

    @Test("no-rule-applies event responds immediately on hot path")
    func noRuleAppliesFastPath() {
        let processTree = FakePipelineProcessTree()

        let responded = DispatchSemaphore(value: 0)
        var allowedResult = false

        let postRespondCalled = DispatchSemaphore(value: 0)

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/allowed"])] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() }
        )
        pipeline.start()

        let event = fileAuthEvent(path: "/unprotected/file") { allowed, _ in
            allowedResult = allowed
            responded.signal()
        }

        pipeline.submit(event)

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult == true)

        let m = pipeline.metrics()
        #expect(m.hotPathRespondedCount == 1)
        #expect(m.slowQueueEnqueueCount == 0)
    }

    @Test("process-level-only event with empty ancestor allowlist responds on hot path")
    func processLevelOnlyFastPath() {
        let processTree = FakePipelineProcessTree()

        let responded = DispatchSemaphore(value: 0)
        var allowedResult = false

        let postRespondCalled = DispatchSemaphore(value: 0)

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/usr/bin/test"])] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() }
        )
        pipeline.start()

        let event = fileAuthEvent(path: "/protected/file") { allowed, _ in
            allowedResult = allowed
            responded.signal()
        }

        pipeline.submit(event)

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult == true)

        let m = pipeline.metrics()
        #expect(m.hotPathRespondedCount == 1)
        #expect(m.slowQueueEnqueueCount == 0)
    }

    @Test("ancestry-required event enters slow queue and responds after evaluation")
    func ancestryRequiredSlowPath() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true
        processTree.ancestorsResult = [AncestorInfo(path: "/usr/bin/parent", teamID: "", signingID: "")]

        let responded = DispatchSemaphore(value: 0)
        var allowedResult = false

        let postRespondCalled = DispatchSemaphore(value: 0)

        let rule = FAARule(
            protectedPathPrefix: "/protected",
            allowedAncestorProcessPaths: ["/usr/bin/parent"]
        )

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [rule] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() }
        )
        pipeline.start()

        let event = fileAuthEvent(path: "/protected/file") { allowed, _ in
            allowedResult = allowed
            responded.signal()
        }

        pipeline.submit(event)

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult == true)

        let m = pipeline.metrics()
        #expect(m.slowQueueEnqueueCount == 1)
        #expect(m.slowPathProcessedCount == 1)
    }

    @Test("full event buffer drops event and responds allow")
    func eventBufferFullDropsEvent() {
        let processTree = FakePipelineProcessTree()

        let responded = DispatchSemaphore(value: 0)
        var allowedResult = false

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in },
            eventBufferCapacity: 1
        )

        let blockingEvent = fileAuthEvent(path: "/first") { _, _ in }
        _ = pipeline.submit(blockingEvent)

        let droppedEvent = fileAuthEvent(path: "/second") { allowed, _ in
            allowedResult = allowed
            responded.signal()
        }
        pipeline.submit(droppedEvent)

        responded.wait()

        #expect(allowedResult == true)

        let m = pipeline.metrics()
        #expect(m.eventBufferDropCount == 1)
    }

    @Test("full slow queue drops event and responds allow")
    func slowQueueFullDropsEvent() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true

        let rule = FAARule(
            protectedPathPrefix: "/protected",
            allowedAncestorProcessPaths: ["/usr/bin/parent"]
        )

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [rule] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in },
            slowQueueCapacity: 1,
            slowWorkerSemaphore: DispatchSemaphore(value: 0)
        )
        pipeline.start()

        let firstResponded = DispatchSemaphore(value: 0)
        let secondResponded = DispatchSemaphore(value: 0)

        let firstEvent = fileAuthEvent(path: "/protected/a") { _, _ in
            firstResponded.signal()
        }
        let secondEvent = fileAuthEvent(path: "/protected/b") { _, _ in
            secondResponded.signal()
        }

        pipeline.submit(firstEvent)

        Thread.sleep(forTimeInterval: 0.05)

        pipeline.submit(secondEvent)

        secondResponded.wait()

        let m = pipeline.metrics()
        #expect(m.slowQueueDropCount == 1)
    }

    @Test("metrics counters are accurate across multiple events")
    func metricsAccuracy() {
        let processTree = FakePipelineProcessTree()

        let allDone = DispatchSemaphore(value: 0)
        let count = OSAllocatedUnfairLock(initialState: 0)

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [] },
            allowlistProvider: { [AllowlistEntry(processPath: "/usr/bin/test")] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in
                let done = count.withLock { c -> Bool in
                    c += 1
                    return c >= 3
                }
                if done { allDone.signal() }
            }
        )
        pipeline.start()

        for _ in 0..<3 {
            let event = fileAuthEvent(path: "/any") { _, _ in }
            pipeline.submit(event)
        }

        allDone.wait()

        let m = pipeline.metrics()
        #expect(m.eventBufferEnqueueCount == 3)
        #expect(m.hotPathProcessedCount == 3)
        #expect(m.hotPathRespondedCount == 3)
        #expect(m.eventBufferDropCount == 0)
    }
}
