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
        pid: Int,
        pidVersion: UInt32,
        path: String,
        isWrite: Bool,
        remainingSeconds: Double,
        reply: @escaping (Bool) -> Void
    )
}

// MARK: -

struct AuthSessionKey: Hashable {
    let pid: pid_t
    let pidVersion: UInt32
    let pathPrefix: String
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

    func hasActiveSession(pid: pid_t, pidVersion: UInt32, prefix: String) -> Bool {
        let key = AuthSessionKey(pid: pid, pidVersion: pidVersion, pathPrefix: prefix)
        return sessions.withLock { store in
            guard let session = store[key] else { return false }
            if session.isActive { return true }
            store.removeValue(forKey: key)
            return false
        }
    }

    func touchSession(pid: pid_t, pidVersion: UInt32, prefix: String) {
        let key = AuthSessionKey(pid: pid, pidVersion: pidVersion, pathPrefix: prefix)
        sessions.withLock { store in
            guard var session = store[key] else { return }
            session.lastAccess = Date()
            store[key] = session
        }
    }

    func createSession(pid: pid_t, pidVersion: UInt32, prefix: String, duration: TimeInterval) {
        let key = AuthSessionKey(pid: pid, pidVersion: pidVersion, pathPrefix: prefix)
        sessions.withLock { store in
            store[key] = AuthSession(lastAccess: Date(), duration: duration)
        }
    }
}

// MARK: - Dispatch

extension AuthorizationGate {
    func requestAuthorization(
        event: FileAuthEvent,
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
                    pid: event.processID,
                    pidVersion: event.processIdentity.pidVersion,
                    prefix: event.path,
                    duration: sessionDuration
                )
            }
            event.respond(allowed, false)
            let decision: PolicyDecision = allowed
                ? .allowed(
                    ruleID: UUID(),
                    ruleName: event.path,
                    ruleSource: .user,
                    matchedCriterion: "Touch ID authorized"
                )
                : .denied(
                    ruleID: UUID(),
                    ruleName: event.path,
                    ruleSource: .user,
                    allowedCriteria: "Touch ID required"
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
            processName: event.processPath,
            signingID: event.signingID,
            pid: Int(event.processID),
            pidVersion: event.processIdentity.pidVersion,
            path: event.path,
            isWrite: event.accessKind == .write,
            remainingSeconds: remainingSeconds
        ) { allowed in
            timer.cancel()
            respondOnce(allowed)
        }
    }
}
