//
//  AuthorizationGateDispatchTests.swift
//  clearancekitTests
//

import Foundation
import os
import Testing

@Suite("AuthorizationGate dispatch")
struct AuthorizationGateDispatchTests {
    @Test("allow response opens a session and responds true")
    func allowOpensSession() async {
        let gate = AuthorizationGate()
        let broadcaster = FakeBroadcaster(answer: true)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let respondedAllowed = OSAllocatedUnfairLock(initialState: false)

        let event = makeEvent(
            deadlineMsFromNow: 5000,
            respond: { allowed, _ in
                respondedAllowed.withLock { $0 = allowed }
                postRespondCalled.signal()
            }
        )

        gate.requestAuthorization(
            event: event,
            rulePrefix: "/Secrets",
            ancestors: [],
            sessionDuration: 300,
            broadcaster: broadcaster,
            postRespond: { _, _, _, _ in }
        )

        _ = postRespondCalled.wait(timeout: .now() + .seconds(2))
        #expect(respondedAllowed.withLock { $0 } == true)
        #expect(gate.hasActiveSession(
            teamID: event.teamID,
            signingID: event.signingID,
            parentPID: event.parentPID,
            parentPIDVersion: event.parentPIDVersion,
            ancestors: [],
            prefix: "/Secrets"
        ) == true)
    }

    @Test("deny response does not open a session")
    func denyLeavesStoreEmpty() async {
        let gate = AuthorizationGate()
        let broadcaster = FakeBroadcaster(answer: false)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let respondedAllowed = OSAllocatedUnfairLock(initialState: true)

        let event = makeEvent(
            deadlineMsFromNow: 5000,
            respond: { allowed, _ in
                respondedAllowed.withLock { $0 = allowed }
                postRespondCalled.signal()
            }
        )

        gate.requestAuthorization(
            event: event,
            rulePrefix: "/Secrets",
            ancestors: [],
            sessionDuration: 300,
            broadcaster: broadcaster,
            postRespond: { _, _, _, _ in }
        )

        _ = postRespondCalled.wait(timeout: .now() + .seconds(2))
        #expect(respondedAllowed.withLock { $0 } == false)
        #expect(gate.hasActiveSession(
            teamID: event.teamID,
            signingID: event.signingID,
            parentPID: event.parentPID,
            parentPIDVersion: event.parentPIDVersion,
            ancestors: [],
            prefix: "/Secrets"
        ) == false)
    }

    @Test("no GUI client — denies without opening a session")
    func withoutClientDenies() async {
        let gate = AuthorizationGate()
        let broadcaster = FakeBroadcaster(answer: nil)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let respondedAllowed = OSAllocatedUnfairLock(initialState: true)

        let event = makeEvent(
            deadlineMsFromNow: 5000,
            respond: { allowed, _ in
                respondedAllowed.withLock { $0 = allowed }
                postRespondCalled.signal()
            }
        )

        gate.requestAuthorization(
            event: event,
            rulePrefix: "/Secrets",
            ancestors: [],
            sessionDuration: 300,
            broadcaster: broadcaster,
            postRespond: { _, _, _, _ in }
        )

        _ = postRespondCalled.wait(timeout: .now() + .seconds(2))
        #expect(respondedAllowed.withLock { $0 } == false)
    }

    // MARK: helpers

    private func makeEvent(
        deadlineMsFromNow: UInt64,
        respond: @escaping @Sendable (Bool, Bool) -> Void
    ) -> FileAuthEvent {
        let timebase: mach_timebase_info_data_t = {
            var info = mach_timebase_info_data_t(); mach_timebase_info(&info); return info
        }()
        let nanos = deadlineMsFromNow * 1_000_000
        let ticks = nanos * UInt64(timebase.denom) / UInt64(timebase.numer)
        let deadline = mach_absolute_time() + ticks
        return FileAuthEvent(
            correlationID: UUID(), operation: .open, accessKind: .write,
            path: "/Secrets", secondaryPath: nil,
            processIdentity: ProcessIdentity(pid: 1234, pidVersion: 7),
            processID: 1234, parentPID: 1, parentPIDVersion: 0, processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            uid: 501, gid: 20, ttyPath: nil, deadline: deadline, respond: respond
        )
    }
}

private final class FakeBroadcaster: AuthorizationBroadcasting, @unchecked Sendable {
    let answer: Bool?
    init(answer: Bool?) { self.answer = answer }

    func requestAuthorizationFromFirstClient(
        processName: String, signingID: String, pid: Int, pidVersion: UInt32,
        path: String, isWrite: Bool, remainingSeconds: Double,
        reply: @escaping (Bool) -> Void
    ) {
        guard let answer else { reply(false); return }
        DispatchQueue.global().async { reply(answer) }
    }
}
