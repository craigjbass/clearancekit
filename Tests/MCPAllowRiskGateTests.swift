//
//  MCPAllowRiskGateTests.swift
//  clearancekitTests
//

import Testing
import Foundation

private let riskyRule = FAARule(
    protectedPathPrefix: "/Users/*/Secrets",
    allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.mdworker_shared")]
)

private let safeRule = FAARule(
    protectedPathPrefix: "/Users/*/Secrets",
    allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.finder")]
)

private let networkingSignature = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.WebKit.Networking")

private let webKitRuleWithoutChecks = FAARule(
    protectedPathPrefix: "/Users/*/Secrets",
    allowedSignatures: [networkingSignature],
    responsibleProcessChecks: []
)

private let webKitRuleWithDefaultChecks = FAARule(
    protectedPathPrefix: "/Users/*/Secrets",
    allowedSignatures: [networkingSignature]
)

@Suite("requireAllowRiskAcknowledgement")
struct MCPAllowRiskGateTests {
    @Test("rule with a broad responsible process check is refused without the flag")
    func broadResponsibleProcessCheckIsRefused() {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Secrets",
            responsibleProcessChecks: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.helper")]
        )

        #expect(throws: AllowRiskNotAcknowledgedError.self) {
            try requireAllowRiskAcknowledgement(for: rule, acknowledgement: .notAcknowledged)
        }
    }

    @Test("risky rule without the flag is refused")
    func riskyRuleWithoutFlagIsRefused() {
        #expect(throws: AllowRiskNotAcknowledgedError.self) {
            try requireAllowRiskAcknowledgement(for: riskyRule, acknowledgement: .notAcknowledged)
        }
    }

    @Test("refusal names the risk, the parameter and that nothing was saved")
    func refusalTextIsComplete() {
        let message = AllowRiskNotAcknowledgedError(risk: .spotlightIndexer).errorDescription ?? ""

        #expect(message.contains("Spotlight indexer"))
        #expect(message.contains("acknowledge_allow_risk"))
        #expect(message.contains("not saved"))
    }

    @Test("risky rule with the flag is accepted")
    func riskyRuleWithFlagIsAccepted() {
        #expect(throws: Never.self) {
            try requireAllowRiskAcknowledgement(for: riskyRule, acknowledgement: .acknowledged)
        }
    }

    @Test("rule without the risk is accepted without the flag")
    func safeRuleWithoutFlagIsAccepted() {
        #expect(throws: Never.self) {
            try requireAllowRiskAcknowledgement(for: safeRule, acknowledgement: .notAcknowledged)
        }
    }

    @Test("rule allowing Networking with no checks is refused without the flag")
    func webKitRuleWithoutChecksIsRefused() {
        #expect(throws: AllowRiskNotAcknowledgedError.self) {
            try requireAllowRiskAcknowledgement(for: webKitRuleWithoutChecks, acknowledgement: .notAcknowledged)
        }
    }

    @Test("rule allowing Networking with no checks is accepted with the flag")
    func webKitRuleWithoutChecksIsAcceptedWithFlag() {
        #expect(throws: Never.self) {
            try requireAllowRiskAcknowledgement(for: webKitRuleWithoutChecks, acknowledgement: .acknowledged)
        }
    }

    @Test("rule allowing Networking with the default checks is accepted without the flag")
    func webKitRuleWithDefaultChecksIsAccepted() {
        #expect(throws: Never.self) {
            try requireAllowRiskAcknowledgement(for: webKitRuleWithDefaultChecks, acknowledgement: .notAcknowledged)
        }
    }

    @Test("WebKit refusal names the risk and the parameter")
    func webKitRefusalText() {
        let message = AllowRiskNotAcknowledgedError(risk: .webKitService).errorDescription ?? ""

        #expect(message.contains("WebKit service"))
        #expect(message.contains("acknowledge_allow_risk"))
        #expect(message.contains("not saved"))
    }
}
