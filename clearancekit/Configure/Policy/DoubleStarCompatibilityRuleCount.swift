//
//  DoubleStarCompatibilityRuleCount.swift
//  clearancekit
//

import Foundation

// A built-in preset rule keeps its shipped matching mode on purpose, so an
// unmodified one is not something the user can act on. A rule counts unless
// it is equal to a built-in preset rule.
func countDoubleStarCompatibilityRules(in rules: [FAARule], builtInPresetRules: [FAARule]) -> Int {
    rules.filter { rule in
        rule.usesDoubleStarCompatibilityMode && !isUnmodifiedBuiltInMatching(rule, builtInPresetRules: builtInPresetRules)
    }.count
}

private func isUnmodifiedBuiltInMatching(_ rule: FAARule, builtInPresetRules: [FAARule]) -> Bool {
    builtInPresetRules.contains(rule)
}
