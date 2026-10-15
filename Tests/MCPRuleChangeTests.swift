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
