//
//  AuthorizationGateTests.swift
//  clearancekitTests
//

import Foundation
import Testing

@Suite("AuthorizationGate session store")
struct AuthorizationGateTests {
    @Test("no session — hasActiveSession is false")
    func emptyStoreReportsNoSession() {
        let gate = AuthorizationGate()
        #expect(gate.hasActiveSession(pid: 1234, pidVersion: 7, prefix: "/Secrets") == false)
    }

    @Test("after createSession — active")
    func createdSessionIsActive() {
        let gate = AuthorizationGate()
        gate.createSession(pid: 1234, pidVersion: 7, prefix: "/Secrets", duration: 60)
        #expect(gate.hasActiveSession(pid: 1234, pidVersion: 7, prefix: "/Secrets") == true)
    }

    @Test("touchSession keeps session alive")
    func touchedSessionStaysActive() {
        let gate = AuthorizationGate()
        gate.createSession(pid: 1234, pidVersion: 7, prefix: "/Secrets", duration: 60)
        gate.touchSession(pid: 1234, pidVersion: 7, prefix: "/Secrets")
        #expect(gate.hasActiveSession(pid: 1234, pidVersion: 7, prefix: "/Secrets") == true)
    }

    @Test("session expires after its duration")
    func expiredSessionIsInactive() {
        let gate = AuthorizationGate()
        gate.createSession(pid: 1234, pidVersion: 7, prefix: "/Secrets", duration: 0.01)
        Thread.sleep(forTimeInterval: 0.02)
        #expect(gate.hasActiveSession(pid: 1234, pidVersion: 7, prefix: "/Secrets") == false)
    }

    @Test("sessions are keyed by pid, pidVersion, and prefix")
    func distinctKeysAreIndependent() {
        let gate = AuthorizationGate()
        gate.createSession(pid: 1234, pidVersion: 7, prefix: "/Secrets", duration: 60)
        #expect(gate.hasActiveSession(pid: 1234, pidVersion: 8, prefix: "/Secrets") == false)
        #expect(gate.hasActiveSession(pid: 9999, pidVersion: 7, prefix: "/Secrets") == false)
        #expect(gate.hasActiveSession(pid: 1234, pidVersion: 7, prefix: "/Other") == false)
    }
}
