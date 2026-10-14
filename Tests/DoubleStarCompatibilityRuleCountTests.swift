//
//  DoubleStarCompatibilityRuleCountTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("DoubleStarCompatibilityRuleCount")
struct DoubleStarCompatibilityRuleCountTests {
    private let presetRuleID = UUID()

    private var presetRule: FAARule {
        FAARule(
            id: presetRuleID,
            protectedPathPrefix: "/private/var/folders/**/Preset-*",
            doubleStarParentMatching: .stopAtDoubleStar
        )
    }

    private func count(_ rules: [FAARule]) -> Int {
        countDoubleStarCompatibilityRules(in: rules, builtInPresetRules: [presetRule])
    }

    @Test("a user ** rule in compatibility mode counts")
    func userRuleCounts() {
        let rule = FAARule(protectedPathPrefix: "/a/**/secret", doubleStarParentMatching: .stopAtDoubleStar)

        #expect(count([rule]) == 1)
    }

    @Test("an unmodified built-in preset rule does not count")
    func unmodifiedPresetRuleDoesNotCount() {
        #expect(count([presetRule]) == 0)
    }

    @Test("a built-in preset rule changed to all nested directories does not count")
    func presetRuleChangedToAllNestedDoesNotCount() {
        let changed = FAARule(
            id: presetRuleID,
            protectedPathPrefix: "/private/var/folders/**/Preset-*",
            doubleStarParentMatching: .allNestedDirectories
        )

        #expect(count([changed]) == 0)
    }

    @Test("a rule with a preset's id and matching mode but another pattern counts")
    func samePresetIdentityWithDifferentPatternCounts() {
        let edited = FAARule(
            id: presetRuleID,
            protectedPathPrefix: "/other/**/path",
            doubleStarParentMatching: .stopAtDoubleStar
        )

        #expect(count([edited]) == 1)
    }

    @Test("a preset rule set to all nested directories is counted when the same id is in compatibility mode")
    func presetIdentityInCompatibilityModeCounts() {
        let allNestedPreset = FAARule(
            id: presetRuleID,
            protectedPathPrefix: "/private/var/folders/**/Preset-*",
            doubleStarParentMatching: .allNestedDirectories
        )
        let compatibilityCopy = FAARule(
            id: presetRuleID,
            protectedPathPrefix: "/private/var/folders/**/Preset-*",
            doubleStarParentMatching: .stopAtDoubleStar
        )

        let counted = countDoubleStarCompatibilityRules(in: [compatibilityCopy], builtInPresetRules: [allNestedPreset])

        #expect(counted == 1)
    }

    @Test("a rule without a ** component never counts")
    func plainRuleNeverCounts() {
        let rule = FAARule(protectedPathPrefix: "/a/secret", doubleStarParentMatching: .stopAtDoubleStar)

        #expect(count([rule]) == 0)
    }
}
