//
//  MCPRuleChangeTests.swift
//  clearancekitTests
//

import Testing
import Foundation

private let customChecks = [ProcessSignature(teamID: "TEAM1", signingID: "com.example.helper")]
private let replacementChecks = [ProcessSignature(teamID: "TEAM2", signingID: "com.example.other")]
private let allowedSignatures = [ProcessSignature(teamID: "TEAM3", signingID: "com.example.app")]

@Suite("MCP rule changes")
struct MCPRuleChangeTests {
    @Test("wildcard responsible_process_checks entries are refused", arguments: [
        ProcessSignature(teamID: "*", signingID: "*"),
        ProcessSignature(teamID: appleTeamID, signingID: "*"),
        ProcessSignature(teamID: "*", signingID: "com.example.helper"),
    ])
    func wildcardChecksAreRefused(check: ProcessSignature) {
        #expect(throws: WildcardResponsibleProcessCheckError.self) {
            try requireNoWildcardResponsibleProcessChecks(customChecks + [check])
        }
    }

    @Test("responsible_process_checks without a wildcard entry are accepted")
    func checksWithoutWildcardAreAccepted() {
        #expect(throws: Never.self) {
            try requireNoWildcardResponsibleProcessChecks(customChecks)
            try requireNoWildcardResponsibleProcessChecks(nil)
        }
    }

    @Test("the wildcard refusal names the entry and the parameter")
    func wildcardRefusalText() {
        let message = WildcardResponsibleProcessCheckError(entry: ProcessSignature(teamID: appleTeamID, signingID: "*")).errorDescription ?? ""

        #expect(message.contains("apple:*"))
        #expect(message.contains("responsible_process_checks"))
    }

    @Test("add without responsible_process_checks gives the default list")
    func addWithoutChecksGivesDefault() {
        let rule = ruleForMCPAdd(
            id: UUID(), protectedPathPrefix: "/a/secret", allowedSignatures: allowedSignatures,
            enforceOnWriteOnly: false, doubleStarParentMatching: .allNestedDirectories,
            responsibleProcessChecks: nil
        )

        #expect(rule.responsibleProcessChecks == defaultResponsibleProcessChecks)
    }

    @Test("add with a custom list keeps it")
    func addWithCustomList() {
        let rule = ruleForMCPAdd(
            id: UUID(), protectedPathPrefix: "/a/secret", allowedSignatures: allowedSignatures,
            enforceOnWriteOnly: false, doubleStarParentMatching: .allNestedDirectories,
            responsibleProcessChecks: customChecks
        )

        #expect(rule.responsibleProcessChecks == customChecks)
    }

    @Test("add with an empty list keeps it empty")
    func addWithEmptyList() {
        let rule = ruleForMCPAdd(
            id: UUID(), protectedPathPrefix: "/a/secret", allowedSignatures: allowedSignatures,
            enforceOnWriteOnly: false, doubleStarParentMatching: .allNestedDirectories,
            responsibleProcessChecks: []
        )

        #expect(rule.responsibleProcessChecks == [])
    }

    @Test("update without responsible_process_checks keeps the stored list")
    func updateWithoutChecksKeepsStoredList() {
        let existing = FAARule(protectedPathPrefix: "/a/secret", responsibleProcessChecks: customChecks)

        let updated = ruleForMCPUpdate(
            existing: existing, allowedSignatures: allowedSignatures,
            enforceOnWriteOnly: false, doubleStarParentMatching: .allNestedDirectories,
            responsibleProcessChecks: nil
        )

        #expect(updated.responsibleProcessChecks == customChecks)
    }

    @Test("update without responsible_process_checks keeps a stored empty list")
    func updateWithoutChecksKeepsStoredEmptyList() {
        let existing = FAARule(protectedPathPrefix: "/a/secret", responsibleProcessChecks: [])

        let updated = ruleForMCPUpdate(
            existing: existing, allowedSignatures: allowedSignatures,
            enforceOnWriteOnly: false, doubleStarParentMatching: .allNestedDirectories,
            responsibleProcessChecks: nil
        )

        #expect(updated.responsibleProcessChecks == [])
    }

    @Test("update with responsible_process_checks replaces the stored list")
    func updateWithChecksReplacesStoredList() {
        let existing = FAARule(protectedPathPrefix: "/a/secret", responsibleProcessChecks: customChecks)

        let updated = ruleForMCPUpdate(
            existing: existing, allowedSignatures: allowedSignatures,
            enforceOnWriteOnly: false, doubleStarParentMatching: .allNestedDirectories,
            responsibleProcessChecks: replacementChecks
        )

        #expect(updated.responsibleProcessChecks == replacementChecks)
    }
}
