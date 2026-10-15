//
//  AuthorizationGate.swift
//  opfilter
//

import Foundation
import os

// MARK: - AuthorizationBroadcasting

protocol AuthorizationBroadcasting: AnyObject, Sendable {
    func requestAuthorizationFromFirstClient(
        processName: String,
        signingID: String,
        teamID: String,
        pid: Int,
        pidVersion: UInt32,
        path: String,
        isWrite: Bool,
        remainingSeconds: Double,
        ancestors: [AncestorInfo],
        reply: @escaping (Bool) -> Void
    )
}

// MARK: - AuthorizationSubject

// A session belongs to the parent of a process that is checked as itself, so
// commands from one shell share a session. A session for a responsible process
// belongs to that responsible process instance, so its WebKit services share
// the session and a new instance of the app asks again.
struct AuthorizationSubject {
    let checkedProcess: CheckedProcess
    let processPath: String
    let teamID: String
    let signingID: String
    let processIdentity: ProcessIdentity
    let sessionOwnerIdentity: ProcessIdentity
    let ancestors: [AncestorInfo]
}

// MARK: -

struct AuthSessionKey: Hashable {
    let teamID: String
    let signingID: String
    let parentPID: pid_t
    let parentPIDVersion: UInt32
    let ancestorChainHash: Int
    let pathPrefix: String
}

private func ancestorChainHash(ancestors: [AncestorInfo]) -> Int {
    var hasher = Hasher()
    for ancestor in ancestors {
        hasher.combine(ancestor.teamID)
        hasher.combine(ancestor.signingID)
    }
    return hasher.finalize()
}

struct AuthSession {
    var lastAccess: Date
    let duration: TimeInterval

    var isActive: Bool {
        Date().timeIntervalSince(lastAccess) < duration
    }
}

final class AuthorizationGate: @unchecked Sendable {
    private let sessions: OSAllocatedUnfairLock<[AuthSessionKey: AuthSession]>

    init() {
        self.sessions = OSAllocatedUnfairLock(initialState: [:])
    }

    func hasActiveSession(
        teamID: String,
        signingID: String,
        parentPID: pid_t,
        parentPIDVersion: UInt32,
        ancestors: [AncestorInfo],
        prefix: String
    ) -> Bool {
        let key = AuthSessionKey(
            teamID: teamID, signingID: signingID,
            parentPID: parentPID, parentPIDVersion: parentPIDVersion,
            ancestorChainHash: ancestorChainHash(ancestors: ancestors),
            pathPrefix: prefix
        )
        return sessions.withLock { store in
            guard let session = store[key] else { return false }
            if session.isActive { return true }
            store.removeValue(forKey: key)
            return false
        }
    }

    func touchSession(
        teamID: String,
        signingID: String,
        parentPID: pid_t,
        parentPIDVersion: UInt32,
        ancestors: [AncestorInfo],
        prefix: String
    ) {
        let key = AuthSessionKey(
            teamID: teamID, signingID: signingID,
            parentPID: parentPID, parentPIDVersion: parentPIDVersion,
            ancestorChainHash: ancestorChainHash(ancestors: ancestors),
            pathPrefix: prefix
        )
        sessions.withLock { store in
            guard var session = store[key] else { return }
            session.lastAccess = Date()
            store[key] = session
        }
    }

    func createSession(
        teamID: String,
        signingID: String,
        parentPID: pid_t,
        parentPIDVersion: UInt32,
        ancestors: [AncestorInfo],
        prefix: String,
        duration: TimeInterval
    ) {
        let key = AuthSessionKey(
            teamID: teamID, signingID: signingID,
            parentPID: parentPID, parentPIDVersion: parentPIDVersion,
            ancestorChainHash: ancestorChainHash(ancestors: ancestors),
            pathPrefix: prefix
        )
        sessions.withLock { store in
            store[key] = AuthSession(lastAccess: Date(), duration: duration)
        }
    }
}

// MARK: - Dispatch

extension AuthorizationGate {
    func requestAuthorization(
        event: FileAuthEvent,
        rulePrefix: String,
        subject: AuthorizationSubject,
        sessionDuration: TimeInterval,
        broadcaster: AuthorizationBroadcasting,
        postRespond: @escaping @Sendable (FileAuthEvent, PolicyDecision, [AncestorInfo], UInt64) -> Void
    ) {
        let remainingMs = MachTime.millisecondsToDeadline(event.deadline)
        let remainingSeconds = max(0.0, Double(remainingMs) / 1000.0 - 0.1)

        let responded = OSAllocatedUnfairLock(initialState: false)
        let gate = self

        let respondOnce: @Sendable (Bool) -> Void = { allowed in
            let skip = responded.withLock { state -> Bool in
                if state { return true }
                state = true
                return false
            }
            guard !skip else { return }
            if allowed {
                gate.createSession(
                    teamID: subject.teamID,
                    signingID: subject.signingID,
                    parentPID: subject.sessionOwnerIdentity.pid,
                    parentPIDVersion: subject.sessionOwnerIdentity.pidVersion,
                    ancestors: subject.ancestors,
                    prefix: rulePrefix,
                    duration: sessionDuration
                )
            }
            event.respond(allowed, false)
            let decision: PolicyDecision = allowed
                ? .allowed(
                    ruleID: UUID(),
                    ruleName: event.path,
                    ruleSource: .user,
                    matchedCriterion: "Touch ID authorized",
                    checkedProcess: subject.checkedProcess
                )
                : .denied(
                    ruleID: UUID(),
                    ruleName: event.path,
                    ruleSource: .user,
                    allowedCriteria: "Touch ID required",
                    checkedProcess: subject.checkedProcess
                )
            postRespond(event, decision, [], 0)
        }

        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
        timer.schedule(deadline: .now() + remainingSeconds)
        timer.setEventHandler {
            respondOnce(false)
            timer.cancel()
        }
        timer.resume()

        broadcaster.requestAuthorizationFromFirstClient(
            processName: subject.processPath,
            signingID: subject.signingID,
            teamID: subject.teamID,
            pid: Int(subject.processIdentity.pid),
            pidVersion: subject.processIdentity.pidVersion,
            path: event.path,
            isWrite: event.accessKind == .write,
            remainingSeconds: remainingSeconds,
            ancestors: subject.ancestors
        ) { allowed in
            timer.cancel()
            respondOnce(allowed)
        }
    }
}
