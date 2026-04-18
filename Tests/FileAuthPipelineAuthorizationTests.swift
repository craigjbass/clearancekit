//
//  FileAuthPipelineAuthorizationTests.swift
//  clearancekitTests
//

import Testing
import Foundation
import os

// MARK: - FakeAuthPipelineProcessTree

private final class FakeAuthPipelineProcessTree: @unchecked Sendable, ProcessTreeProtocol {
    var containsResult = true
    var ancestorsResult: [AncestorInfo] = []

    func insert(_ record: ProcessRecord) {}
    func remove(identity: ProcessIdentity) {}

    func contains(identity: ProcessIdentity) -> Bool { containsResult }
    func ancestors(of identity: ProcessIdentity) -> [AncestorInfo] { ancestorsResult }
    func allRecords() -> [ProcessRecord] { [] }
}

// MARK: - Helpers

private func authorizationEvent(
    pid: pid_t = 4242,
    pidVersion: UInt32 = 3,
    path: String = "/Secrets/file.txt",
    teamID: String = "ABCDE12345",
    respond: @escaping @Sendable (Bool, Bool) -> Void
) -> FileAuthEvent {
    FileAuthEvent(
        correlationID: UUID(),
        operation: .open,
        accessKind: .write,
        path: path,
        secondaryPath: nil,
        processIdentity: ProcessIdentity(pid: pid, pidVersion: pidVersion),
        processID: pid,
        parentPID: 1,
        parentPIDVersion: 0,
        processPath: "/Apps/Example",
        teamID: teamID,
        signingID: "com.example.app",
        uid: 501,
        gid: 20,
        ttyPath: nil,
        deadline: 0,
        respond: respond
    )
}

private func authorizationRule() -> FAARule {
    FAARule(
        protectedPathPrefix: "/Secrets",
        requiresAuthorization: true,
        authorizationSessionDuration: 300
    )
}

// MARK: - FileAuthPipelineAuthorizationTests

@Suite("FileAuthPipeline authorization routing", .serialized)
struct FileAuthPipelineAuthorizationTests {

    @Test("event with active session is allowed without calling authorizationHandler")
    func activeSessionAllowsWithoutHandler() {
        let processTree = FakeAuthPipelineProcessTree()
        let gate = AuthorizationGate()
        gate.createSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 1, parentPIDVersion: 0, ancestors: [], prefix: "/Secrets", duration: 300)

        let responded = DispatchSemaphore(value: 0)
        var allowedResult = false
        let postRespondCalled = DispatchSemaphore(value: 0)
        let handlerCalledLock = OSAllocatedUnfairLock(initialState: false)

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [authorizationRule()] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() },
            authorizationGate: gate,
            authorizationHandler: { _, _, _, _ in
                handlerCalledLock.withLock { $0 = true }
            }
        )
        pipeline.start()

        let event = authorizationEvent(pid: 4242, pidVersion: 3) { allowed, _ in
            allowedResult = allowed
            responded.signal()
        }

        pipeline.submit(event)

        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult == true)
        #expect(handlerCalledLock.withLock { $0 } == false)
    }

    @Test("event with no session calls authorizationHandler with event and session duration")
    func noSessionCallsAuthorizationHandler() {
        let processTree = FakeAuthPipelineProcessTree()
        let gate = AuthorizationGate()

        let handlerCalled = DispatchSemaphore(value: 0)
        let capturedDuration = OSAllocatedUnfairLock<TimeInterval>(initialState: 0)

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [authorizationRule()] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in },
            authorizationGate: gate,
            authorizationHandler: { _, duration, _, _ in
                capturedDuration.withLock { $0 = duration }
                handlerCalled.signal()
            }
        )
        pipeline.start()

        let event = authorizationEvent(pid: 4242, pidVersion: 3) { _, _ in }

        pipeline.submit(event)

        handlerCalled.wait()

        #expect(capturedDuration.withLock { $0 } == 300)
    }
}
