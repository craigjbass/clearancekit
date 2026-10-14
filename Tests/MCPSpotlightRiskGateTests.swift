//
//  MCPSpotlightRiskGateTests.swift
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

@Suite("requireSpotlightRiskAcknowledgement")
struct MCPSpotlightRiskGateTests {
    @Test("risky rule without the flag is refused")
    func riskyRuleWithoutFlagIsRefused() {
        #expect(throws: SpotlightRiskNotAcknowledgedError.self) {
            try requireSpotlightRiskAcknowledgement(for: riskyRule, acknowledgement: .notAcknowledged)
        }
    }

    @Test("refusal names the risk, the parameter and that nothing was saved")
    func refusalTextIsComplete() {
        let message = SpotlightRiskNotAcknowledgedError().errorDescription ?? ""

        #expect(message.contains("Spotlight indexer"))
        #expect(message.contains("acknowledge_spotlight_risk"))
        #expect(message.contains("not saved"))
    }

    @Test("risky rule with the flag is accepted")
    func riskyRuleWithFlagIsAccepted() {
        #expect(throws: Never.self) {
            try requireSpotlightRiskAcknowledgement(for: riskyRule, acknowledgement: .acknowledged)
        }
    }

    @Test("rule without the risk is accepted without the flag")
    func safeRuleWithoutFlagIsAccepted() {
        #expect(throws: Never.self) {
            try requireSpotlightRiskAcknowledgement(for: safeRule, acknowledgement: .notAcknowledged)
        }
    }
}
