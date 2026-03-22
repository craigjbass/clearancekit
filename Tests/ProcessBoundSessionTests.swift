//
//  ProcessBoundSessionTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("ProcessBoundSession")
struct ProcessBoundSessionTests {

    // MARK: - SessionGrant

    @Test("session is valid before expiry")
    func sessionValidBeforeExpiry() {
        let now = Date()
        let grant = SessionGrant(
            processIdentity: ProcessIdentity(pid: 100, pidVersion: 1),
            grantedAt: now,
            duration: 60
        )

        #expect(grant.isValid(at: now.addingTimeInterval(30)))
    }

    @Test("session is invalid after expiry")
    func sessionInvalidAfterExpiry() {
        let now = Date()
        let grant = SessionGrant(
            processIdentity: ProcessIdentity(pid: 100, pidVersion: 1),
            grantedAt: now,
            duration: 60
        )

        #expect(!grant.isValid(at: now.addingTimeInterval(61)))
    }

    @Test("session expires exactly at boundary")
    func sessionExpiresAtBoundary() {
        let now = Date()
        let grant = SessionGrant(
            processIdentity: ProcessIdentity(pid: 100, pidVersion: 1),
            grantedAt: now,
            duration: 60
        )

        #expect(!grant.isValid(at: now.addingTimeInterval(60)))
    }

    @Test("expiresAt returns correct timestamp")
    func expiresAtReturnsCorrectTimestamp() {
        let now = Date()
        let grant = SessionGrant(
            processIdentity: ProcessIdentity(pid: 100, pidVersion: 1),
            grantedAt: now,
            duration: 300
        )

        #expect(grant.expiresAt == now.addingTimeInterval(300))
    }

    // MARK: - ProcessSessionStore grant and lookup

    @Test("grant creates valid session")
    func grantCreatesValidSession() {
        let store = ProcessSessionStore()
        let identity = ProcessIdentity(pid: 42, pidVersion: 7)

        let session = store.grant(for: identity, duration: 60)

        #expect(session.processIdentity == identity)
        #expect(session.duration == 60)
        #expect(store.hasValidSession(for: identity))
    }

    @Test("hasValidSession returns false for unknown process")
    func hasValidSessionReturnsFalseForUnknownProcess() {
        let store = ProcessSessionStore()
        let identity = ProcessIdentity(pid: 99, pidVersion: 1)

        #expect(!store.hasValidSession(for: identity))
    }

    @Test("hasValidSession returns false after session expires")
    func hasValidSessionReturnsFalseAfterExpiry() {
        var currentTime = Date()
        let store = ProcessSessionStore(clock: { currentTime })
        let identity = ProcessIdentity(pid: 42, pidVersion: 7)

        _ = store.grant(for: identity, duration: 60)
        currentTime = currentTime.addingTimeInterval(61)

        #expect(!store.hasValidSession(for: identity))
    }

    @Test("hasValidSession returns true within session window")
    func hasValidSessionReturnsTrueWithinWindow() {
        var currentTime = Date()
        let store = ProcessSessionStore(clock: { currentTime })
        let identity = ProcessIdentity(pid: 42, pidVersion: 7)

        _ = store.grant(for: identity, duration: 60)
        currentTime = currentTime.addingTimeInterval(30)

        #expect(store.hasValidSession(for: identity))
    }

    // MARK: - PID version isolation

    @Test("different pidVersion does not share session")
    func differentPidVersionDoesNotShareSession() {
        let store = ProcessSessionStore()
        let original = ProcessIdentity(pid: 42, pidVersion: 7)
        let reused = ProcessIdentity(pid: 42, pidVersion: 8)

        _ = store.grant(for: original, duration: 60)

        #expect(store.hasValidSession(for: original))
        #expect(!store.hasValidSession(for: reused))
    }

    @Test("same PID different version after grant gets separate session")
    func samePidDifferentVersionGetsSeparateSession() {
        let store = ProcessSessionStore()
        let version1 = ProcessIdentity(pid: 42, pidVersion: 1)
        let version2 = ProcessIdentity(pid: 42, pidVersion: 2)

        _ = store.grant(for: version1, duration: 60)
        _ = store.grant(for: version2, duration: 120)

        #expect(store.hasValidSession(for: version1))
        #expect(store.hasValidSession(for: version2))
    }

    // MARK: - Revocation

    @Test("revoke removes a specific session")
    func revokeRemovesSpecificSession() {
        let store = ProcessSessionStore()
        let identity1 = ProcessIdentity(pid: 42, pidVersion: 1)
        let identity2 = ProcessIdentity(pid: 43, pidVersion: 1)

        _ = store.grant(for: identity1, duration: 60)
        _ = store.grant(for: identity2, duration: 60)
        store.revoke(for: identity1)

        #expect(!store.hasValidSession(for: identity1))
        #expect(store.hasValidSession(for: identity2))
    }

    @Test("revokeAll removes all sessions")
    func revokeAllRemovesAllSessions() {
        let store = ProcessSessionStore()
        let identity1 = ProcessIdentity(pid: 42, pidVersion: 1)
        let identity2 = ProcessIdentity(pid: 43, pidVersion: 1)

        _ = store.grant(for: identity1, duration: 60)
        _ = store.grant(for: identity2, duration: 60)
        store.revokeAll()

        #expect(!store.hasValidSession(for: identity1))
        #expect(!store.hasValidSession(for: identity2))
    }

    // MARK: - Active session count

    @Test("activeSessionCount returns only non-expired sessions")
    func activeSessionCountReturnsOnlyNonExpiredSessions() {
        var currentTime = Date()
        let store = ProcessSessionStore(clock: { currentTime })

        _ = store.grant(for: ProcessIdentity(pid: 1, pidVersion: 1), duration: 30)
        _ = store.grant(for: ProcessIdentity(pid: 2, pidVersion: 1), duration: 120)
        _ = store.grant(for: ProcessIdentity(pid: 3, pidVersion: 1), duration: 120)

        currentTime = currentTime.addingTimeInterval(60)

        #expect(store.activeSessionCount() == 2)
    }

    @Test("activeSessionCount returns zero when all expired")
    func activeSessionCountReturnsZeroWhenAllExpired() {
        var currentTime = Date()
        let store = ProcessSessionStore(clock: { currentTime })

        _ = store.grant(for: ProcessIdentity(pid: 1, pidVersion: 1), duration: 30)
        _ = store.grant(for: ProcessIdentity(pid: 2, pidVersion: 1), duration: 30)

        currentTime = currentTime.addingTimeInterval(60)

        #expect(store.activeSessionCount() == 0)
    }

    // MARK: - Expired session cleanup

    @Test("removeExpired cleans up stale entries")
    func removeExpiredCleansUpStaleEntries() {
        var currentTime = Date()
        let store = ProcessSessionStore(clock: { currentTime })

        _ = store.grant(for: ProcessIdentity(pid: 1, pidVersion: 1), duration: 30)
        _ = store.grant(for: ProcessIdentity(pid: 2, pidVersion: 1), duration: 120)

        currentTime = currentTime.addingTimeInterval(60)
        store.removeExpired()

        #expect(!store.hasValidSession(for: ProcessIdentity(pid: 1, pidVersion: 1)))
        #expect(store.hasValidSession(for: ProcessIdentity(pid: 2, pidVersion: 1)))
    }

    // MARK: - Session re-grant

    @Test("granting again refreshes the session")
    func grantAgainRefreshesSession() {
        var currentTime = Date()
        let store = ProcessSessionStore(clock: { currentTime })
        let identity = ProcessIdentity(pid: 42, pidVersion: 1)

        _ = store.grant(for: identity, duration: 60)
        currentTime = currentTime.addingTimeInterval(50)
        _ = store.grant(for: identity, duration: 60)
        currentTime = currentTime.addingTimeInterval(50)

        #expect(store.hasValidSession(for: identity))
    }

    // MARK: - SessionDuration enum

    @Test("SessionDuration raw values match expected seconds")
    func sessionDurationRawValues() {
        #expect(SessionDuration.oneMinute.rawValue == 60)
        #expect(SessionDuration.fiveMinutes.rawValue == 300)
        #expect(SessionDuration.tenMinutes.rawValue == 600)
    }
}
