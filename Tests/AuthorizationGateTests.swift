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
        #expect(gate.hasActiveSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets") == false)
    }

    @Test("after createSession — active")
    func createdSessionIsActive() {
        let gate = AuthorizationGate()
        gate.createSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets", duration: 60)
        #expect(gate.hasActiveSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets") == true)
    }

    @Test("touchSession keeps session alive")
    func touchedSessionStaysActive() {
        let gate = AuthorizationGate()
        gate.createSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets", duration: 60)
        gate.touchSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets")
        #expect(gate.hasActiveSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets") == true)
    }

    @Test("session expires after its duration")
    func expiredSessionIsInactive() {
        let gate = AuthorizationGate()
        gate.createSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets", duration: 0.01)
        Thread.sleep(forTimeInterval: 0.02)
        #expect(gate.hasActiveSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets") == false)
    }

    @Test("sessions are keyed by teamID, signingID, parentPID, parentPIDVersion, ancestors, and prefix")
    func distinctKeysAreIndependent() {
        let gate = AuthorizationGate()
        gate.createSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets", duration: 60)
        // Different parent — different shell, no session
        #expect(gate.hasActiveSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 99, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets") == false)
        // Different parent PID version — different instance of same parent process
        #expect(gate.hasActiveSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 2, ancestors: [], prefix: "/Secrets") == false)
        // Different ancestor chain
        let ancestors = [AncestorInfo(path: "/Applications/Terminal.app/Contents/MacOS/Terminal", teamID: "apple", signingID: "com.apple.Terminal")]
        #expect(gate.hasActiveSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: ancestors, prefix: "/Secrets") == false)
        // Different signing identity
        #expect(gate.hasActiveSession(teamID: "ZZZZZ99999", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets") == false)
        #expect(gate.hasActiveSession(teamID: "ABCDE12345", signingID: "com.other.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets") == false)
        // Different rule prefix
        #expect(gate.hasActiveSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Other") == false)
    }

    @Test("same ancestry chain re-uses session")
    func sameAncestryChainReusesSession() {
        let gate = AuthorizationGate()
        let ancestors = [AncestorInfo(path: "/Applications/Terminal.app/Contents/MacOS/Terminal", teamID: "apple", signingID: "com.apple.Terminal")]
        gate.createSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: ancestors, prefix: "/Secrets", duration: 60)
        // Same ancestry — session hit
        #expect(gate.hasActiveSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: ancestors, prefix: "/Secrets") == true)
    }

    @Test("same app re-launched from same parent inherits session")
    func sameParentInheritsSession() {
        let gate = AuthorizationGate()
        // First invocation authorizes
        gate.createSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets", duration: 60)
        // Second invocation from same parent — session hit even though it has a different pid
        #expect(gate.hasActiveSession(teamID: "ABCDE12345", signingID: "com.example.app", parentPID: 50, parentPIDVersion: 1, ancestors: [], prefix: "/Secrets") == true)
    }
}
