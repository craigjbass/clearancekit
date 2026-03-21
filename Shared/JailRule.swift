//
//  JailRule.swift
//  clearancekit
//
//  Domain type and evaluation logic for App Jail — restricting a process
//  to only a specified set of path prefixes.
//

import Foundation

// MARK: - JailRule

public struct JailRule: Identifiable, Codable, Equatable {
    public let id: UUID
    public let name: String
    public let source: RuleSource
    public var jailedSignature: ProcessSignature
    public var allowedPathPrefixes: [String]

    public init(
        id: UUID = UUID(),
        name: String,
        source: RuleSource = .user,
        jailedSignature: ProcessSignature,
        allowedPathPrefixes: [String] = []
    ) {
        self.id = id
        self.name = name
        self.source = source
        self.jailedSignature = jailedSignature
        self.allowedPathPrefixes = allowedPathPrefixes
    }
}

// MARK: - Jail policy evaluation

public func checkJailPolicy(
    jailRules: [JailRule],
    path: String,
    teamID: String,
    signingID: String
) -> PolicyDecision {
    guard !jailRules.isEmpty else { return .noRuleApplies }

    let resolvedTeamID = teamID.isEmpty ? appleTeamID : teamID
    guard let rule = jailRules.first(where: { $0.jailedSignature.matches(resolvedTeamID: resolvedTeamID, signingID: signingID) }) else {
        return .noRuleApplies
    }

    for prefix in rule.allowedPathPrefixes {
        let trimmed = prefix.hasSuffix("/") ? String(prefix.dropLast()) : prefix
        guard path.hasPrefix(trimmed) else { continue }
        let rest = path.dropFirst(trimmed.count)
        guard rest.isEmpty || rest.hasPrefix("/") else { continue }
        return .jailAllowed(ruleID: rule.id, ruleName: rule.name, matchedPrefix: prefix)
    }

    return .jailDenied(ruleID: rule.id, ruleName: rule.name, allowedPrefixes: rule.allowedPathPrefixes)
}
