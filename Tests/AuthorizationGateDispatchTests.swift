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
            subject: itselfSubject(of: event),
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
            subject: itselfSubject(of: event),
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
            subject: itselfSubject(of: event),
            sessionDuration: 300,
            broadcaster: broadcaster,
            postRespond: { _, _, _, _ in }
        )

        _ = postRespondCalled.wait(timeout: .now() + .seconds(2))
        #expect(respondedAllowed.withLock { $0 } == false)
    }

    @Test("responsible process subject is shown in the prompt and opens its own session")
    func responsibleSubjectPromptsAndOpensSession() {
        let gate = AuthorizationGate()
        let broadcaster = FakeBroadcaster(answer: true)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let capturedDecision = OSAllocatedUnfairLock<CheckedProcess?>(initialState: nil)
        let safariFacts = ProcessFacts(processPath: "/Applications/Safari.app/Contents/MacOS/Safari", teamID: appleTeamID, signingID: "com.apple.Safari")
        let safariAncestors = [AncestorInfo(path: "/sbin/launchd", teamID: appleTeamID, signingID: "com.apple.xpc.launchd")]
        let subject = AuthorizationSubject(
            checkedProcess: .responsible(safariFacts),
            processPath: safariFacts.processPath,
            teamID: safariFacts.teamID,
            signingID: safariFacts.signingID,
            processIdentity: ProcessIdentity(pid: 300, pidVersion: 4),
            sessionOwnerIdentity: ProcessIdentity(pid: 300, pidVersion: 4),
            ancestors: safariAncestors
        )

        let event = makeEvent(deadlineMsFromNow: 5000, respond: { _, _ in })

        gate.requestAuthorization(
            event: event,
            rulePrefix: "/Secrets",
            subject: subject,
            sessionDuration: 300,
            broadcaster: broadcaster,
            postRespond: { _, decision, _, _ in
                capturedDecision.withLock { $0 = decision.checkedProcess }
                postRespondCalled.signal()
            }
        )

        _ = postRespondCalled.wait(timeout: .now() + .seconds(2))
        let prompt = broadcaster.lastPrompt.withLock { $0 }
        #expect(prompt?.processName == "/Applications/Safari.app/Contents/MacOS/Safari")
        #expect(prompt?.signingID == "com.apple.Safari")
        #expect(prompt?.teamID == appleTeamID)
        #expect(prompt?.pid == 300)
        #expect(prompt?.pidVersion == 4)
        #expect(capturedDecision.withLock { $0 } == .responsible(safariFacts))
        #expect(gate.hasActiveSession(
            teamID: appleTeamID,
            signingID: "com.apple.Safari",
            parentPID: 300,
            parentPIDVersion: 4,
            ancestors: safariAncestors,
            prefix: "/Secrets"
        ) == true)
        #expect(gate.hasActiveSession(
            teamID: event.teamID,
            signingID: event.signingID,
            parentPID: event.parentPID,
            parentPIDVersion: event.parentPIDVersion,
            ancestors: [],
            prefix: "/Secrets"
        ) == false)
    }

    // MARK: helpers

    private func itselfSubject(of event: FileAuthEvent) -> AuthorizationSubject {
        AuthorizationSubject(
            checkedProcess: .itself,
            processPath: event.processPath,
            teamID: event.teamID,
            signingID: event.signingID,
            processIdentity: event.processIdentity,
            sessionOwnerIdentity: ProcessIdentity(pid: event.parentPID, pidVersion: event.parentPIDVersion),
            ancestors: []
        )
    }

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
            path: "/Secrets", secondaryPath: nil, movedEntryKind: .noDirectory,
            processIdentity: ProcessIdentity(pid: 1234, pidVersion: 7),
            responsibleIdentity: ProcessIdentity(pid: 1234, pidVersion: 7),
            processID: 1234, parentPID: 1, parentPIDVersion: 0, processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            uid: 501, gid: 20, ttyPath: nil, deadline: deadline, respond: respond
        )
    }
}

private struct AuthorizationPrompt: Sendable {
    let processName: String
    let signingID: String
    let teamID: String
    let pid: Int
    let pidVersion: UInt32
}

private final class FakeBroadcaster: AuthorizationBroadcasting, @unchecked Sendable {
    let answer: Bool?
    let lastPrompt = OSAllocatedUnfairLock<AuthorizationPrompt?>(initialState: nil)
    init(answer: Bool?) { self.answer = answer }

    func requestAuthorizationFromFirstClient(
        processName: String, signingID: String, teamID: String, pid: Int, pidVersion: UInt32,
        path: String, isWrite: Bool, remainingSeconds: Double, ancestors: [AncestorInfo],
        reply: @escaping (Bool) -> Void
    ) {
        lastPrompt.withLock { $0 = AuthorizationPrompt(processName: processName, signingID: signingID, teamID: teamID, pid: pid, pidVersion: pidVersion) }
        guard let answer else { reply(false); return }
        DispatchQueue.global().async { reply(answer) }
    }
}
