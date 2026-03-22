//
//  ProcessBoundSession.swift
//  Shared
//
//  Process-bound session management for reducing repeated biometric prompts.
//  A session ties an authenticated action window to a specific process identity
//  (PID + pidVersion), preventing PID-reuse attacks while letting a verified
//  process perform multiple operations without repeated Touch ID prompts.
//

import Foundation
import os

// MARK: - SessionDuration

enum SessionDuration: TimeInterval {
    case oneMinute = 60
    case fiveMinutes = 300
    case tenMinutes = 600
}

// MARK: - SessionGrant

struct SessionGrant: Sendable {
    let processIdentity: ProcessIdentity
    let grantedAt: Date
    let duration: TimeInterval

    var expiresAt: Date {
        grantedAt.addingTimeInterval(duration)
    }

    func isValid(at now: Date) -> Bool {
        now < expiresAt
    }
}

// MARK: - SessionStoreProtocol

protocol SessionStoreProtocol: Sendable {
    func grant(for identity: ProcessIdentity, duration: TimeInterval) -> SessionGrant
    func hasValidSession(for identity: ProcessIdentity) -> Bool
    func revoke(for identity: ProcessIdentity)
    func revokeAll()
    func activeSessionCount() -> Int
}

// MARK: - ProcessSessionStore

final class ProcessSessionStore: SessionStoreProtocol, @unchecked Sendable {
    private let storage = OSAllocatedUnfairLock(initialState: [ProcessIdentity: SessionGrant]())
    private let clock: @Sendable () -> Date

    init(clock: @escaping @Sendable () -> Date = { Date() }) {
        self.clock = clock
    }

    func grant(for identity: ProcessIdentity, duration: TimeInterval) -> SessionGrant {
        let session = SessionGrant(
            processIdentity: identity,
            grantedAt: clock(),
            duration: duration
        )
        storage.withLock { $0[identity] = session }
        return session
    }

    func hasValidSession(for identity: ProcessIdentity) -> Bool {
        storage.withLock { sessions in
            guard let session = sessions[identity] else { return false }
            guard session.isValid(at: clock()) else {
                sessions[identity] = nil
                return false
            }
            return true
        }
    }

    func revoke(for identity: ProcessIdentity) {
        storage.withLock { $0[identity] = nil }
    }

    func revokeAll() {
        storage.withLock { $0.removeAll() }
    }

    func activeSessionCount() -> Int {
        let now = clock()
        return storage.withLock { sessions in
            sessions.values.filter { $0.isValid(at: now) }.count
        }
    }

    func removeExpired() {
        let now = clock()
        storage.withLock { sessions in
            sessions = sessions.filter { $0.value.isValid(at: now) }
        }
    }
}
