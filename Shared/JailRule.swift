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

/// Evaluates path access for a process already known to be under `rule`, without
/// re-checking the signing ID. Used for inherited jail processes whose signing ID
/// does not match the rule's jailedSignature.
public func checkJailPath(rule: JailRule, path: String) -> PolicyDecision {
    for pattern in rule.allowedPathPrefixes {
        guard pathMatchesPattern(path, pattern: pattern) else { continue }
        return .jailAllowed(ruleID: rule.id, ruleName: rule.name, matchedPrefix: pattern)
    }
    return .jailDenied(ruleID: rule.id, ruleName: rule.name, allowedPrefixes: rule.allowedPathPrefixes)
}

public func checkJailPaths(rule: JailRule, path: String, secondaryPath: String?) -> PolicyDecision {
    let primaryDecision = checkJailPath(rule: rule, path: path)
    guard let secondaryPath else { return primaryDecision }
    guard primaryDecision.isAllowed else { return primaryDecision }
    return checkJailPath(rule: rule, path: secondaryPath)
}

public func checkJailPolicy(
    jailRules: [JailRule],
    path: String,
    teamID: String,
    signingID: String
) -> PolicyDecision {
    guard !jailRules.isEmpty else { return .noRuleApplies }

    guard let rule = jailRules.first(where: { $0.jailedSignature.matches(resolvedTeamID: teamID, signingID: signingID) }) else {
        return .noRuleApplies
    }

    for pattern in rule.allowedPathPrefixes {
        guard pathMatchesPattern(path, pattern: pattern) else { continue }
        return .jailAllowed(ruleID: rule.id, ruleName: rule.name, matchedPrefix: pattern)
    }

    return .jailDenied(ruleID: rule.id, ruleName: rule.name, allowedPrefixes: rule.allowedPathPrefixes)
}

/// Walks ancestors to find the first one whose signing ID matches a jail rule,
/// then evaluates the path against that rule. Returns nil if no ancestor is jailed.
public func checkAncestorJailPolicy(
    jailRules: [JailRule],
    path: String,
    ancestors: [AncestorInfo]
) -> PolicyDecision? {
    guard !jailRules.isEmpty else { return nil }

    for ancestor in ancestors {
        guard let rule = jailRules.first(where: { $0.jailedSignature.matches(resolvedTeamID: ancestor.teamID, signingID: ancestor.signingID) }) else { continue }
        return checkJailPath(rule: rule, path: path)
    }
    return nil
}

private func pathMatchesPattern(_ path: String, pattern: String) -> Bool {
    let pathSegments = path.split(separator: "/").map(String.init)
    let patternSegments = pattern.split(separator: "/").map(String.init)
    var pathIndex = 0
    for patternSegment in patternSegments {
        if patternSegment == "**" {
            return true
        }
        guard pathIndex < pathSegments.count else { return false }
        guard segmentMatches(pathSegments[pathIndex], pattern: patternSegment) else { return false }
        pathIndex += 1
    }
    return pathIndex == pathSegments.count
}

private func segmentMatches(_ segment: String, pattern: String) -> Bool {
    guard pattern.contains("***") else {
        return pattern == "*" || segment == pattern
    }
    let parts = pattern.components(separatedBy: "***")
    let prefix = parts[0]
    let suffix = parts[parts.count - 1]
    guard segment.count >= prefix.count + suffix.count else { return false }
    return segment.hasPrefix(prefix) && segment.hasSuffix(suffix)
}
