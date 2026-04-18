//
//  PolicyDecision+AuthorizationTests.swift
//  clearancekitTests
//

import Foundation
import Testing

@Suite("Authorization decisions")
struct PolicyDecisionAuthorizationTests {
    @Test("authorizedSignatures match returns requiresAuthorization")
    func authorizedSignatureRequestsPrompt() {
        let rule = FAARule(
            protectedPathPrefix: "/Secrets",
            authorizedSignatures: [ProcessSignature(teamID: "ABCDE12345", signingID: "com.example.app")],
            authorizationSessionDuration: 600
        )
        let decision = checkFAAPolicy(
            rules: [rule], path: "/Secrets/file.txt", processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            accessKind: .write, ancestors: []
        )
        guard case .requiresAuthorization(_, _, _, let criterion, let duration) = decision else {
            Issue.record("expected requiresAuthorization, got \(decision)"); return
        }
        #expect(criterion == "authorizedSignature")
        #expect(duration == 600)
        #expect(decision.isAllowed == false)
    }

    @Test("requiresAuthorization with a valid team ID returns requiresAuthorization")
    func catchAllRequiresAuthorization() {
        let rule = FAARule(
            protectedPathPrefix: "/Secrets",
            requiresAuthorization: true
        )
        let decision = checkFAAPolicy(
            rules: [rule], path: "/Secrets/file.txt", processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            accessKind: .write, ancestors: []
        )
        guard case .requiresAuthorization(_, _, _, let criterion, _) = decision else {
            Issue.record("expected requiresAuthorization, got \(decision)"); return
        }
        #expect(criterion == "requiresAuthorization")
    }

    @Test("requiresAuthorization with empty team ID falls through to denied")
    func unsignedBypassesPromptAndIsDenied() {
        let rule = FAARule(
            protectedPathPrefix: "/Secrets",
            requiresAuthorization: true
        )
        let decision = checkFAAPolicy(
            rules: [rule], path: "/Secrets/file.txt", processPath: "/Apps/Example",
            teamID: "", signingID: "",
            accessKind: .write, ancestors: []
        )
        if case .requiresAuthorization = decision {
            Issue.record("unsigned process must not get a Touch ID prompt")
        }
        #expect(decision.isAllowed == false)
    }

    @Test("allowedSignatures takes priority over authorizedSignatures")
    func allowedBeatsAuthorized() {
        let signature = ProcessSignature(teamID: "ABCDE12345", signingID: "com.example.app")
        let rule = FAARule(
            protectedPathPrefix: "/Secrets",
            allowedSignatures: [signature],
            authorizedSignatures: [signature],
            requiresAuthorization: true
        )
        let decision = checkFAAPolicy(
            rules: [rule], path: "/Secrets/file.txt", processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            accessKind: .write, ancestors: []
        )
        guard case .allowed = decision else {
            Issue.record("expected .allowed, got \(decision)"); return
        }
    }

    @Test("enforceOnWriteOnly skips the rule for reads even when authorization is set")
    func writeOnlyRuleSkippedOnRead() {
        let rule = FAARule(
            protectedPathPrefix: "/Secrets",
            enforceOnWriteOnly: true,
            requiresAuthorization: true
        )
        let decision = checkFAAPolicy(
            rules: [rule], path: "/Secrets/file.txt", processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            accessKind: .read, ancestors: []
        )
        guard case .noRuleApplies = decision else {
            Issue.record("expected .noRuleApplies, got \(decision)"); return
        }
    }
}
