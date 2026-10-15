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
    var recordsByIdentity: [ProcessIdentity: ProcessRecord] = [:]

    func insert(_ record: ProcessRecord) {}
    func remove(identity: ProcessIdentity) {}

    func contains(identity: ProcessIdentity) -> Bool {
        containsResult
    }

    func ancestors(of identity: ProcessIdentity) -> [AncestorInfo] {
        ancestorsResult
    }

    func record(of identity: ProcessIdentity) -> ProcessRecord? {
        recordsByIdentity[identity]
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
    accessKind: AccessKind = .write,
    responsibleIdentity: ProcessIdentity = identity(),
    respond: @escaping @Sendable (Bool, Bool) -> Void
) -> FileAuthEvent {
    FileAuthEvent(
        correlationID: UUID(),
        operation: .open,
        accessKind: accessKind,
        path: path,
        secondaryPath: nil,
        movedEntryKind: .noDirectory,
        processIdentity: identity(),
        responsibleIdentity: responsibleIdentity,
        processID: 100,
        parentPID: 1,
        parentPIDVersion: 0,
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

private func directoryOperationEvent(
    operation: FileOperation,
    path: String,
    secondaryPath: String?,
    movedEntryKind: MovedEntryKind,
    processPath: String = "/tmp/poc",
    teamID: String = "",
    signingID: String = "",
    respond: @escaping @Sendable (Bool, Bool) -> Void
) -> FileAuthEvent {
    FileAuthEvent(
        correlationID: UUID(),
        operation: operation,
        accessKind: .write,
        path: path,
        secondaryPath: secondaryPath,
        movedEntryKind: movedEntryKind,
        processIdentity: identity(),
        responsibleIdentity: identity(),
        processID: 100,
        parentPID: 1,
        parentPIDVersion: 0,
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

enum AncestryOutcome: CaseIterable, Sendable {
    case matching
    case mismatching

    var ancestorPath: String {
        switch self {
        case .matching: return "/usr/bin/parent"
        case .mismatching: return "/usr/bin/stranger"
        }
    }

    var expectedAllowed: Bool {
        switch self {
        case .matching: return true
        case .mismatching: return false
        }
    }
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

    @Test("write-only rule on a read responds with cache=false (cache safety)")
    func writeOnlyRuleReadResponseDoesNotCache() {
        // A write-only rule covers /protected. A read of /protected/file
        // hits .processLevelOnly because the rule's path prefix matches —
        // the rule itself is then skipped by checkFAAPolicy because the
        // access is a read, but the responder must still use cache=false
        // so that a subsequent write to the same vnode by the same process
        // re-triggers the auth callback. Caching the read-allow would let
        // a later write bypass the rule entirely.
        let processTree = FakePipelineProcessTree()

        let responded = DispatchSemaphore(value: 0)
        var allowedResult = false
        var cacheResult = true  // start as true so a missing assignment fails the test

        let postRespondCalled = DispatchSemaphore(value: 0)

        let writeOnlyRule = FAARule(
            protectedPathPrefix: "/protected",
            allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.opendirectoryd")],
            enforceOnWriteOnly: true
        )

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [writeOnlyRule] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() }
        )
        pipeline.start()

        let event = fileAuthEvent(path: "/protected/file", accessKind: .read) { allowed, cache in
            allowedResult = allowed
            cacheResult = cache
            responded.signal()
        }

        pipeline.submit(event)

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult == true)
        #expect(cacheResult == false)
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

    @Test("denies when secondary path is protected and process is not allowed")
    func secondaryPathDenied() {
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

        let event = FileAuthEvent(
            correlationID: UUID(),
            operation: .rename,
            accessKind: .write,
            path: "/unprotected/source",
            secondaryPath: "/protected/dest",
            movedEntryKind: .noDirectory,
            processIdentity: identity(),
            responsibleIdentity: identity(),
            processID: 100,
            parentPID: 1,
            parentPIDVersion: 0,
            processPath: "/usr/bin/test",
            teamID: "",
            signingID: "",
            uid: 501,
            gid: 20,
            ttyPath: nil,
            deadline: 0,
            respond: { allowed, _ in
                allowedResult = allowed
                responded.signal()
            }
        )

        pipeline.submit(event)

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult == false)
    }

    // MARK: - Bundle protection integration

    private func makeBundleEvaluator(allowExternalUpdater: Bool) -> BundleProtectionEvaluator {
        let cache = BundleCodesignCache(
            ttl: 60,
            executableEnumerator: { _ in ["/Applications/Foo.app/Contents/MacOS/Foo"] },
            signatureReader: { _ in "BUNDLE_TEAM" }
        )
        return BundleProtectionEvaluator(
            cache: cache,
            updaterSignaturesProvider: {
                allowExternalUpdater
                    ? [BundleUpdaterSignature(teamID: "UPDATER_TEAM", signingID: "com.updater.tool")]
                    : []
            }
        )
    }

    @Test("bundle write routes to slow path, evaluator allows external updater")
    func bundleWriteRoutesToSlowPath() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true
        let evaluator = makeBundleEvaluator(allowExternalUpdater: true)

        let responded = DispatchSemaphore(value: 0)
        var allowedResult = false
        let postRespondCalled = DispatchSemaphore(value: 0)
        var postRespondDecision: PolicyDecision?

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, decision, _, _ in
                postRespondDecision = decision
                postRespondCalled.signal()
            },
            bundleProtectionEvaluator: evaluator
        )
        pipeline.start()

        let event = fileAuthEvent(
            path: "/Applications/Foo.app/Contents/MacOS/Foo",
            teamID: "UPDATER_TEAM",
            signingID: "com.updater.tool",
            accessKind: .write
        ) { allowed, _ in
            allowedResult = allowed
            responded.signal()
        }

        pipeline.submit(event)
        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult == true)
        if case .allowed(_, _, _, let criterion, _) = postRespondDecision {
            #expect(criterion == "external updater")
        } else {
            Issue.record("Expected .allowed from evaluator, got \(String(describing: postRespondDecision))")
        }
    }

    @Test("bundle write with mismatching process identity: denied by evaluator")
    func bundleWriteDeniedByEvaluator() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true
        let evaluator = makeBundleEvaluator(allowExternalUpdater: false)

        let responded = DispatchSemaphore(value: 0)
        var allowedResult = true
        let postRespondCalled = DispatchSemaphore(value: 0)

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() },
            bundleProtectionEvaluator: evaluator
        )
        pipeline.start()

        let event = fileAuthEvent(
            path: "/Applications/Foo.app/Contents/MacOS/Foo",
            teamID: "WRONG_TEAM",
            signingID: "com.wrong.process",
            accessKind: .write
        ) { allowed, _ in
            allowedResult = allowed
            responded.signal()
        }

        pipeline.submit(event)
        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult == false)
    }

    @Test("bundle read is NOT routed to slow path by isBundleWrite")
    func bundleReadNotRouted() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true

        let responded = DispatchSemaphore(value: 0)
        let postRespondCalled = DispatchSemaphore(value: 0)
        var postRespondDecision: PolicyDecision?

        let evaluator = makeBundleEvaluator(allowExternalUpdater: true)
        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, decision, _, _ in
                postRespondDecision = decision
                postRespondCalled.signal()
            },
            bundleProtectionEvaluator: evaluator
        )
        pipeline.start()

        let event = fileAuthEvent(
            path: "/Applications/Foo.app/Contents/MacOS/Foo",
            accessKind: .read
        ) { _, _ in responded.signal() }

        pipeline.submit(event)
        responded.wait()
        postRespondCalled.wait()

        if case .noRuleApplies = postRespondDecision {
            // correct — read events fall through to normal policy
        } else {
            Issue.record("Expected .noRuleApplies for read, got \(String(describing: postRespondDecision))")
        }
    }

    @Test("rename swap from inside an app bundle onto a protected directory is denied")
    func renameSwapFromBundleOntoProtectedDirectoryIsDenied() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true
        let evaluator = makeBundleEvaluator(allowExternalUpdater: true)
        let responded = DispatchSemaphore(value: 0)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let allowedResult = OSAllocatedUnfairLock(initialState: true)

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedProcessPaths: ["/allowed"])] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() },
            bundleProtectionEvaluator: evaluator
        )
        pipeline.start()

        pipeline.submit(directoryOperationEvent(
            operation: .rename,
            path: "/Applications/Foo.app/Contents/Resources/evildir",
            secondaryPath: "/Users/develop/goal",
            movedEntryKind: .directory,
            teamID: "UPDATER_TEAM",
            signingID: "com.updater.tool"
        ) { allowed, _ in
            allowedResult.withLock { $0 = allowed }
            responded.signal()
        })

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult.withLock { $0 } == false)
    }

    @Test("bundle denial wins over a rule that needs authorization")
    func bundleDenialWinsOverAuthorization() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true
        let evaluator = makeBundleEvaluator(allowExternalUpdater: false)
        let responded = DispatchSemaphore(value: 0)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let allowedResult = OSAllocatedUnfairLock(initialState: true)
        let authorizationRequestCount = OSAllocatedUnfairLock(initialState: 0)

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [FAARule(protectedPathPrefix: "/Users/develop/goal/*", requiresAuthorization: true)] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() },
            authorizationHandler: { _, _, _, _ in authorizationRequestCount.withLock { $0 += 1 } },
            bundleProtectionEvaluator: evaluator
        )
        pipeline.start()

        pipeline.submit(directoryOperationEvent(
            operation: .rename,
            path: "/Applications/Foo.app/Contents/Resources/evildir",
            secondaryPath: "/Users/develop/goal",
            movedEntryKind: .directory,
            teamID: "WRONG_TEAM",
            signingID: "com.wrong.process"
        ) { allowed, _ in
            allowedResult.withLock { $0 = allowed }
            responded.signal()
        })

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult.withLock { $0 } == false)
        #expect(authorizationRequestCount.withLock { $0 } == 0)
    }

    @Test("directory operation on a parent of a protected path is denied", arguments: [FileOperation.rename, .clone, .copyfile])
    func directoryOperationOnParentIsDenied(operation: FileOperation) {
        let responded = DispatchSemaphore(value: 0)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let allowedResult = OSAllocatedUnfairLock(initialState: true)

        let pipeline = FileAuthPipeline(
            processTree: FakePipelineProcessTree(),
            rulesProvider: { [FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedProcessPaths: ["/allowed"])] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() }
        )
        pipeline.start()

        pipeline.submit(directoryOperationEvent(operation: operation, path: "/Users/develop/goal", secondaryPath: "/private/tmp/ck_clone_out", movedEntryKind: .directory) { allowed, _ in
            allowedResult.withLock { $0 = allowed }
            responded.signal()
        })

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult.withLock { $0 } == false)
    }

    @Test("directory rename on a parent of an ancestry-gated rule is decided on the slow path by ancestry", arguments: [AncestryOutcome.mismatching, .matching])
    func directoryRenameOnParentOfAncestryGatedRule(outcome: AncestryOutcome) {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true
        processTree.ancestorsResult = [AncestorInfo(path: outcome.ancestorPath, teamID: "", signingID: "")]
        let responded = DispatchSemaphore(value: 0)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let allowedResult = OSAllocatedUnfairLock(initialState: false)

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedAncestorProcessPaths: ["/usr/bin/parent"])] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() }
        )
        pipeline.start()

        pipeline.submit(directoryOperationEvent(operation: .rename, path: "/Users/develop/goal", secondaryPath: "/private/tmp/out", movedEntryKind: .directory) { allowed, _ in
            allowedResult.withLock { $0 = allowed }
            responded.signal()
        })

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult.withLock { $0 } == outcome.expectedAllowed)
        #expect(pipeline.metrics().slowQueueEnqueueCount == 1)
    }

    @Test("open of a parent of a protected path is not covered by any rule")
    func openOfParentIsAllowedAndCacheable() {
        let responded = DispatchSemaphore(value: 0)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: (allowed: false, cache: false))

        let pipeline = FileAuthPipeline(
            processTree: FakePipelineProcessTree(),
            rulesProvider: { [FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedProcessPaths: ["/allowed"])] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() }
        )
        pipeline.start()

        pipeline.submit(directoryOperationEvent(operation: .open, path: "/Users/develop/goal", secondaryPath: nil, movedEntryKind: .noDirectory) { allowed, cache in
            result.withLock { $0 = (allowed, cache) }
            responded.signal()
        })

        responded.wait()
        postRespondCalled.wait()

        #expect(result.withLock { $0.allowed } == true)
        #expect(result.withLock { $0.cache } == true)
    }

    @Test("rename of a regular file that has the path of a parent is not covered by any rule")
    func renameOfRegularFileWithParentPathIsNotCovered() {
        let responded = DispatchSemaphore(value: 0)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let allowedResult = OSAllocatedUnfairLock(initialState: false)
        var postRespondDecision: PolicyDecision?

        let pipeline = FileAuthPipeline(
            processTree: FakePipelineProcessTree(),
            rulesProvider: { [FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedProcessPaths: ["/allowed"])] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, decision, _, _ in
                postRespondDecision = decision
                postRespondCalled.signal()
            }
        )
        pipeline.start()

        pipeline.submit(directoryOperationEvent(operation: .rename, path: "/Users/develop/goal", secondaryPath: "/Users/develop/goal2", movedEntryKind: .noDirectory) { allowed, _ in
            allowedResult.withLock { $0 = allowed }
            responded.signal()
        })

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult.withLock { $0 } == true)
        guard case .noRuleApplies = postRespondDecision else {
            Issue.record("Expected .noRuleApplies, got \(String(describing: postRespondDecision))")
            return
        }
    }

    @Test("regular file swapped onto a protected directory is denied")
    func regularFileSwappedOntoProtectedDirectoryIsDenied() {
        let responded = DispatchSemaphore(value: 0)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let allowedResult = OSAllocatedUnfairLock(initialState: true)

        let pipeline = FileAuthPipeline(
            processTree: FakePipelineProcessTree(),
            rulesProvider: { [FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedProcessPaths: ["/allowed"])] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() }
        )
        pipeline.start()

        pipeline.submit(directoryOperationEvent(operation: .rename, path: "/Users/develop/planted-file", secondaryPath: "/Users/develop/goal", movedEntryKind: .directory) { allowed, _ in
            allowedResult.withLock { $0 = allowed }
            responded.signal()
        })

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult.withLock { $0 } == false)
    }

    @Test("allow for a directory move that no rule covers is not cached")
    func uncoveredDirectoryMoveIsNotCached() {
        let responded = DispatchSemaphore(value: 0)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: (allowed: false, cache: true))

        let pipeline = FileAuthPipeline(
            processTree: FakePipelineProcessTree(),
            rulesProvider: { [FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedProcessPaths: ["/allowed"])] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() }
        )
        pipeline.start()

        pipeline.submit(directoryOperationEvent(operation: .rename, path: "/Users/develop/other", secondaryPath: "/Users/develop/other2", movedEntryKind: .directory) { allowed, cache in
            result.withLock { $0 = (allowed, cache) }
            responded.signal()
        })

        responded.wait()
        postRespondCalled.wait()

        #expect(result.withLock { $0.allowed } == true)
        #expect(result.withLock { $0.cache } == false)
    }

    @Test("allow for a globally allowed directory move is not cached")
    func globallyAllowedDirectoryMoveIsNotCached() {
        let responded = DispatchSemaphore(value: 0)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: (allowed: false, cache: true))

        let pipeline = FileAuthPipeline(
            processTree: FakePipelineProcessTree(),
            rulesProvider: { [FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedProcessPaths: ["/allowed"])] },
            allowlistProvider: { [AllowlistEntry(processPath: "/tmp/poc")] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() }
        )
        pipeline.start()

        pipeline.submit(directoryOperationEvent(operation: .rename, path: "/Users/develop/goal", secondaryPath: "/private/tmp/out", movedEntryKind: .directory) { allowed, cache in
            result.withLock { $0 = (allowed, cache) }
            responded.signal()
        })

        responded.wait()
        postRespondCalled.wait()

        #expect(result.withLock { $0.allowed } == true)
        #expect(result.withLock { $0.cache } == false)
    }

    @Test("allow for a regular file move that no rule covers is cached")
    func uncoveredRegularFileMoveIsCached() {
        let responded = DispatchSemaphore(value: 0)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: (allowed: false, cache: false))

        let pipeline = FileAuthPipeline(
            processTree: FakePipelineProcessTree(),
            rulesProvider: { [FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedProcessPaths: ["/allowed"])] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() }
        )
        pipeline.start()

        pipeline.submit(directoryOperationEvent(operation: .rename, path: "/Users/develop/other.txt", secondaryPath: "/Users/develop/other2.txt", movedEntryKind: .noDirectory) { allowed, cache in
            result.withLock { $0 = (allowed, cache) }
            responded.signal()
        })

        responded.wait()
        postRespondCalled.wait()

        #expect(result.withLock { $0.allowed } == true)
        #expect(result.withLock { $0.cache } == true)
    }
}

// MARK: - Responsible process

private let networkingProcessPath = "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
private let networkingSigningID = "com.apple.WebKit.Networking"
private let webKitResponsibleIdentity = ProcessIdentity(pid: 300, pidVersion: 4)

private func responsibleRecord(signingID: String, teamID: String, identity: ProcessIdentity = webKitResponsibleIdentity) -> ProcessRecord {
    ProcessRecord(
        identity: identity,
        parentIdentity: ProcessIdentity(pid: 1, pidVersion: 1),
        path: "/Applications/Example.app/Contents/MacOS/Example",
        teamID: teamID,
        signingID: signingID,
        uid: 501,
        gid: 20
    )
}

private func safariOnlyRule() -> FAARule {
    FAARule(
        protectedPathPrefix: "/protected",
        allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.Safari")]
    )
}

private struct PipelineOutcome {
    let allowed: Bool
    let cache: Bool
    let decision: PolicyDecision
}

private func runPipeline(
    processTree: FakePipelineProcessTree,
    rules: [FAARule],
    allowlist: [AllowlistEntry] = [],
    event makeEvent: (@escaping @Sendable (Bool, Bool) -> Void) -> FileAuthEvent
) -> PipelineOutcome {
    let responded = DispatchSemaphore(value: 0)
    let postRespondCalled = DispatchSemaphore(value: 0)
    let response = OSAllocatedUnfairLock(initialState: (allowed: false, cache: false))
    let capturedDecision = OSAllocatedUnfairLock<PolicyDecision?>(initialState: nil)

    let pipeline = FileAuthPipeline(
        processTree: processTree,
        rulesProvider: { rules },
        allowlistProvider: { allowlist },
        ancestorAllowlistProvider: { [] },
        postRespond: { _, decision, _, _ in
            capturedDecision.withLock { $0 = decision }
            postRespondCalled.signal()
        }
    )
    pipeline.start()

    pipeline.submit(makeEvent { allowed, cache in
        response.withLock { $0 = (allowed, cache) }
        responded.signal()
    })

    responded.wait()
    postRespondCalled.wait()

    let finalResponse = response.withLock { $0 }
    guard let decision = capturedDecision.withLock({ $0 }) else {
        preconditionFailure("postRespond ran without a decision")
    }
    return PipelineOutcome(allowed: finalResponse.allowed, cache: finalResponse.cache, decision: decision)
}

private func networkingEvent(
    path: String,
    responsibleIdentity eventResponsibleIdentity: ProcessIdentity = webKitResponsibleIdentity,
    respond: @escaping @Sendable (Bool, Bool) -> Void
) -> FileAuthEvent {
    fileAuthEvent(
        path: path,
        processPath: networkingProcessPath,
        teamID: appleTeamID,
        signingID: networkingSigningID,
        accessKind: .read,
        responsibleIdentity: eventResponsibleIdentity,
        respond: respond
    )
}

@Suite("FileAuthPipeline responsible process", .serialized)
struct FileAuthPipelineResponsibleProcessTests {

    @Test("Networking event is denied when its responsible process is not allowed on the protected path")
    func networkingDeniedForDisallowedResponsibleProcess() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true
        processTree.recordsByIdentity = [webKitResponsibleIdentity: responsibleRecord(signingID: "com.example.tool", teamID: "TEAM123")]

        let outcome = runPipeline(processTree: processTree, rules: [safariOnlyRule()]) { networkingEvent(path: "/protected/file", respond: $0) }

        #expect(outcome.allowed == false)
    }

    @Test("Networking event is allowed when its responsible process is allowed on the protected path")
    func networkingAllowedForAllowedResponsibleProcess() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true
        let safari = responsibleRecord(signingID: "com.apple.Safari", teamID: appleTeamID)
        processTree.recordsByIdentity = [webKitResponsibleIdentity: safari]

        let outcome = runPipeline(processTree: processTree, rules: [safariOnlyRule()]) { networkingEvent(path: "/protected/file", respond: $0) }

        #expect(outcome.allowed == true)
        #expect(outcome.decision.checkedProcess == .responsible(ProcessFacts(processPath: safari.path, teamID: appleTeamID, signingID: "com.apple.Safari")))
    }

    @Test("Networking event is denied when the responsible process has no record")
    func networkingDeniedForMissingResponsibleRecord() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true

        let outcome = runPipeline(processTree: processTree, rules: [safariOnlyRule()]) { networkingEvent(path: "/protected/file", respond: $0) }

        #expect(outcome.allowed == false)
        #expect(outcome.decision.checkedProcess == .unknownResponsible)
    }

    @Test("Networking event is denied when the responsible identity is the process itself")
    func networkingDeniedWhenResponsibleIsItself() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true
        processTree.recordsByIdentity = [identity(): responsibleRecord(signingID: "com.apple.Safari", teamID: appleTeamID, identity: identity())]

        let outcome = runPipeline(processTree: processTree, rules: [safariOnlyRule()]) {
            networkingEvent(path: "/protected/file", responsibleIdentity: identity(), respond: $0)
        }

        #expect(outcome.allowed == false)
        #expect(outcome.decision.checkedProcess == .unknownResponsible)
    }

    @Test("Networking event that no rule covers is allowed without cache")
    func networkingNoRuleAppliesIsNotCached() {
        let outcome = runPipeline(processTree: FakePipelineProcessTree(), rules: [safariOnlyRule()]) { networkingEvent(path: "/unprotected/file", respond: $0) }

        #expect(outcome.allowed == true)
        #expect(outcome.cache == false)
    }

    @Test("globally allowed Networking event is allowed without cache")
    func networkingGloballyAllowedIsNotCached() {
        let allowlist = [AllowlistEntry(signingID: networkingSigningID, platformBinary: true)]

        let outcome = runPipeline(processTree: FakePipelineProcessTree(), rules: [safariOnlyRule()], allowlist: allowlist) { networkingEvent(path: "/protected/file", respond: $0) }

        #expect(outcome.allowed == true)
        #expect(outcome.cache == false)
    }

    @Test("ordinary process event that no rule covers is allowed with cache")
    func ordinaryNoRuleAppliesIsCached() {
        let outcome = runPipeline(processTree: FakePipelineProcessTree(), rules: [safariOnlyRule()]) { fileAuthEvent(path: "/unprotected/file", respond: $0) }

        #expect(outcome.allowed == true)
        #expect(outcome.cache == true)
    }

    @Test("globally allowed ordinary process event is allowed with cache")
    func ordinaryGloballyAllowedIsCached() {
        let allowlist = [AllowlistEntry(processPath: "/usr/bin/test")]

        let outcome = runPipeline(processTree: FakePipelineProcessTree(), rules: [safariOnlyRule()], allowlist: allowlist) { fileAuthEvent(path: "/protected/file", respond: $0) }

        #expect(outcome.allowed == true)
        #expect(outcome.cache == true)
    }
}

// MARK: - MovedEntryKind

@Suite("MovedEntryKind")
struct MovedEntryKindTests {
    @Test("a directory source is a directory move")
    func directorySourceIsDirectoryMove() {
        #expect(MovedEntryKind(fileModes: [S_IFDIR | 0o755]) == .directory)
    }

    @Test("a regular file source moves no directory")
    func regularFileSourceMovesNoDirectory() {
        #expect(MovedEntryKind(fileModes: [S_IFREG | 0o644]) == .noDirectory)
    }

    @Test("a symbolic link to a directory moves no directory")
    func symbolicLinkMovesNoDirectory() {
        #expect(MovedEntryKind(fileModes: [S_IFLNK | 0o755]) == .noDirectory)
    }

    @Test("a regular file swapped with an existing directory is a directory move")
    func fileSwappedWithDirectoryIsDirectoryMove() {
        #expect(MovedEntryKind(fileModes: [S_IFREG | 0o644, S_IFDIR | 0o755]) == .directory)
    }

    @Test("an event that moves no entry moves no directory")
    func noFileModesMovesNoDirectory() {
        #expect(MovedEntryKind(fileModes: []) == .noDirectory)
    }
}

// MARK: - FileAuthEvent.reach

@Suite("FileAuthEvent.reach")
struct FileAuthEventReachTests {
    @Test("a directory move or copy reaches the subtree", arguments: [FileOperation.rename, .clone, .copyfile])
    func directoryMoveReachesSubtree(operation: FileOperation) {
        let event = directoryOperationEvent(operation: operation, path: "/a", secondaryPath: "/b", movedEntryKind: .directory) { _, _ in }
        #expect(event.reach == .subtree)
    }

    @Test("a move or copy of a non-directory reaches only its paths", arguments: [FileOperation.rename, .clone, .copyfile])
    func nonDirectoryMoveReachesSinglePath(operation: FileOperation) {
        let event = directoryOperationEvent(operation: operation, path: "/a", secondaryPath: "/b", movedEntryKind: .noDirectory) { _, _ in }
        #expect(event.reach == .singlePath)
    }

    @Test("an operation that moves nothing reaches only its paths", arguments: [FileOperation.open, .unlink, .link, .create, .truncate, .readdir, .exchangedata])
    func nonMovingOperationReachesSinglePath(operation: FileOperation) {
        let event = directoryOperationEvent(operation: operation, path: "/a", secondaryPath: "/b", movedEntryKind: .directory) { _, _ in }
        #expect(event.reach == .singlePath)
    }
}
