//
//  AuthorizationGate.swift
//  opfilter
//

import Foundation
import os

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
