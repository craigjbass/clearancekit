//
//  DoubleStarCompatibilityRuleCount.swift
//  clearancekit
//

import Foundation

// A built-in preset rule keeps its shipped matching mode on purpose, so an
// unmodified one is not something the user can act on. A rule counts unless
// both its id and its matching mode equal those of a built-in preset rule.
func countDoubleStarCompatibilityRules(in rules: [FAARule], builtInPresetRules: [FAARule]) -> Int {
    rules.filter { rule in
        rule.usesDoubleStarCompatibilityMode && !isUnmodifiedBuiltInMatching(rule, builtInPresetRules: builtInPresetRules)
    }.count
}

private func isUnmodifiedBuiltInMatching(_ rule: FAARule, builtInPresetRules: [FAARule]) -> Bool {
    builtInPresetRules.contains { $0.id == rule.id && $0.doubleStarParentMatching == rule.doubleStarParentMatching }
}
