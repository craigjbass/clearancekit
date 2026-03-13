//
//  FAAPolicy.swift
//  clearancekit
//
//  Created by Craig J. Bass on 16/02/2026.
//

import Foundation

// MARK: - Constants

/// Sentinel team ID used to represent Apple platform binaries.
/// Apple's own binaries carry an empty team ID in the ES audit token;
/// this identifier lets policy rules reference them explicitly.
public let appleTeamID = "apple"

// MARK: - PolicyDecision

public enum PolicyDecision {
    /// Path not covered by any rule — default allow.
    case noRuleApplies
    /// Covered by a rule and a specific criterion matched.
    case allowed(matchedCriterion: String)
    /// Covered by a rule but no criterion matched — denied.
    case denied(ruleID: UUID, rule: String, allowedCriteria: String)

    public var isAllowed: Bool {
        if case .denied = self { return false }
        return true
    }

    public var matchedRuleID: UUID? {
        if case .denied(let ruleID, _, _) = self { return ruleID }
        return nil
    }

    public var reason: String {
        switch self {
        case .noRuleApplies:
            return "No rule applies — default allow"
        case .allowed(let criterion):
            return "Allowed: matched \(criterion)"
        case .denied(_, let rule, let criteria):
            return "Denied by rule \"\(rule)\" — allowed: \(criteria)"
        }
    }
}

// MARK: - FAARule

public struct FAARule: Identifiable, Codable {
    public let id: UUID
    public let protectedPathPrefix: String

    /// The literal path prefix passed to `es_mute_path`.
    /// For wildcard patterns this is the last fully-literal directory component;
    /// the kernel delivers a superset of events which the policy filter narrows down.
    public var esMutePath: String { mutePath(for: protectedPathPrefix) }
    public let allowedProcessPaths: [String]
    public let allowedTeamIDs: [String]
    public let allowedSigningIDs: [String]
    public let allowedAncestorProcessPaths: [String]
    public let allowedAncestorTeamIDs: [String]
    public let allowedAncestorSigningIDs: [String]

    public init(
        id: UUID = UUID(),
        protectedPathPrefix: String,
        allowedProcessPaths: [String] = [],
        allowedTeamIDs: [String] = [],
        allowedSigningIDs: [String] = [],
        allowedAncestorProcessPaths: [String] = [],
        allowedAncestorTeamIDs: [String] = [],
        allowedAncestorSigningIDs: [String] = []
    ) {
        self.id = id
        self.protectedPathPrefix = protectedPathPrefix
        self.allowedProcessPaths = allowedProcessPaths
        self.allowedTeamIDs = allowedTeamIDs
        self.allowedSigningIDs = allowedSigningIDs
        self.allowedAncestorProcessPaths = allowedAncestorProcessPaths
        self.allowedAncestorTeamIDs = allowedAncestorTeamIDs
        self.allowedAncestorSigningIDs = allowedAncestorSigningIDs
    }
}

// MARK: - Policy

public let clearancekitTeamID = "37KMK6XFTT"

public let faaPolicy: [FAARule] = [
    // Protect the daemon's policy storage directory. Only processes signed by the
    // clearancekit team may open files under this path — this covers the daemon
    // itself, the GUI app, and the system extension. Any other process (including
    // a compromised user process) is denied at the kernel level before it can
    // read or tamper with the stored rules.
    FAARule(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
        protectedPathPrefix: "/Library/Application Support/clearancekit",
        allowedTeamIDs: [clearancekitTeamID]
    ),
    // Example: only Finder and Terminal may access secrets
    FAARule(
        protectedPathPrefix: "/opt/clearancekit/secrets",
        allowedProcessPaths: [
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
        ],
        allowedAncestorSigningIDs: ["com.apple.Terminal"]
    ),
]

// MARK: - Path matching

/// Returns the literal path prefix to pass to `es_mute_path` for a given pattern.
/// Stops at the first path component that contains a wildcard character.
public func mutePath(for pattern: String) -> String {
    var literal: [String] = []
    for component in pattern.split(separator: "/", omittingEmptySubsequences: false).map(String.init) {
        if component.contains("*") || component.contains("?") { break }
        literal.append(component)
    }
    let result = literal.joined(separator: "/")
    return result.isEmpty ? "/" : result
}

/// Returns true if `path` falls within the directory described by `pattern`.
///
/// Supported wildcards:
/// - `*`  matches any characters within a single path component (no `/`)
/// - `**` as a standalone component matches any number of path levels
/// - `?`  matches any single character within a component
///
/// A pattern with no wildcards behaves identically to the original prefix check.
public func pathIsProtected(_ path: String, by pattern: String) -> Bool {
    guard pattern.contains("*") || pattern.contains("?") else {
        let trimmed = pattern.hasSuffix("/") ? String(pattern.dropLast()) : pattern
        guard path.hasPrefix(trimmed) else { return false }
        let rest = path.dropFirst(trimmed.count)
        return rest.isEmpty || rest.hasPrefix("/")
    }
    let pathParts  = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
    let patternParts = pattern.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
    return componentPrefixMatches(path: pathParts[...], pattern: patternParts[...])
}

private func componentPrefixMatches(path: ArraySlice<String>, pattern: ArraySlice<String>) -> Bool {
    if pattern.isEmpty { return true }
    if path.isEmpty { return false }
    let pat = pattern.first!
    if pat == "**" {
        let rest = pattern.dropFirst()
        var remaining = path
        while true {
            if componentPrefixMatches(path: remaining, pattern: rest) { return true }
            if remaining.isEmpty { return false }
            remaining = remaining.dropFirst()
        }
    }
    guard globMatches(string: path.first!, pattern: pat) else { return false }
    return componentPrefixMatches(path: path.dropFirst(), pattern: pattern.dropFirst())
}

/// Matches a single path component against a glob pattern (`*`, `?` within the component).
private func globMatches(string: String, pattern: String) -> Bool {
    if pattern == "*" { return true }
    if !pattern.contains("*") && !pattern.contains("?") { return string == pattern }
    func match(_ si: String.Index, _ pi: String.Index) -> Bool {
        if pi == pattern.endIndex { return si == string.endIndex }
        if pattern[pi] == "*" {
            var ci = si
            let nextPi = pattern.index(after: pi)
            while true {
                if match(ci, nextPi) { return true }
                if ci == string.endIndex { return false }
                ci = string.index(after: ci)
            }
        }
        guard si < string.endIndex, pattern[pi] == "?" || pattern[pi] == string[si] else { return false }
        return match(string.index(after: si), pattern.index(after: pi))
    }
    return match(string.startIndex, pattern.startIndex)
}

// MARK: - Policy evaluation

public func checkFAAPolicy(
    rules: [FAARule],
    path: String,
    processPath: String,
    teamID: String,
    signingID: String,
    ancestors: [AncestorInfo] = []
) -> PolicyDecision {
    for rule in rules {
        guard pathIsProtected(path, by: rule.protectedPathPrefix) else { continue }

        if !rule.allowedProcessPaths.isEmpty && rule.allowedProcessPaths.contains(processPath) {
            return .allowed(matchedCriterion: "process path \(processPath)")
        }

        // teamID and signingID are AND: both specified constraints must be satisfied.
        // Apple platform binaries carry an empty team ID; resolve to appleTeamID for matching.
        let resolvedTeamID = teamID.isEmpty ? appleTeamID : teamID
        let teamOK    = rule.allowedTeamIDs.isEmpty    || rule.allowedTeamIDs.contains(resolvedTeamID)
        let signingOK = rule.allowedSigningIDs.isEmpty || rule.allowedSigningIDs.contains(signingID)
        if (!rule.allowedTeamIDs.isEmpty || !rule.allowedSigningIDs.isEmpty) && teamOK && signingOK {
            var parts: [String] = []
            if !rule.allowedTeamIDs.isEmpty    { parts.append("team ID \(resolvedTeamID)") }
            if !rule.allowedSigningIDs.isEmpty { parts.append("signing ID \(signingID)") }
            return .allowed(matchedCriterion: parts.joined(separator: " and "))
        }

        if !rule.allowedAncestorProcessPaths.isEmpty,
           let match = ancestors.first(where: { rule.allowedAncestorProcessPaths.contains($0.path) }) {
            return .allowed(matchedCriterion: "ancestor process path \(match.path)")
        }

        // Ancestor teamID and signingID are also AND across both constraints.
        for ancestor in ancestors {
            let resolvedAncestorTeamID = ancestor.teamID.isEmpty ? appleTeamID : ancestor.teamID
            let aTeamOK    = rule.allowedAncestorTeamIDs.isEmpty    || rule.allowedAncestorTeamIDs.contains(resolvedAncestorTeamID)
            let aSigningOK = rule.allowedAncestorSigningIDs.isEmpty || rule.allowedAncestorSigningIDs.contains(ancestor.signingID)
            if (!rule.allowedAncestorTeamIDs.isEmpty || !rule.allowedAncestorSigningIDs.isEmpty) && aTeamOK && aSigningOK {
                var parts: [String] = []
                if !rule.allowedAncestorTeamIDs.isEmpty    { parts.append("ancestor team ID \(resolvedAncestorTeamID)") }
                if !rule.allowedAncestorSigningIDs.isEmpty { parts.append("ancestor signing ID \(ancestor.signingID)") }
                parts.append("(\(ancestor.path))")
                return .allowed(matchedCriterion: parts.joined(separator: " and "))
            }
        }

        var criteria: [String] = []
        if !rule.allowedProcessPaths.isEmpty {
            criteria.append("process paths: \(rule.allowedProcessPaths.joined(separator: ", "))")
        }
        if !rule.allowedTeamIDs.isEmpty {
            criteria.append("team IDs: \(rule.allowedTeamIDs.joined(separator: ", "))")
        }
        if !rule.allowedSigningIDs.isEmpty {
            criteria.append("signing IDs: \(rule.allowedSigningIDs.joined(separator: ", "))")
        }
        if !rule.allowedAncestorProcessPaths.isEmpty {
            criteria.append("ancestor paths: \(rule.allowedAncestorProcessPaths.joined(separator: ", "))")
        }
        if !rule.allowedAncestorTeamIDs.isEmpty {
            criteria.append("ancestor team IDs: \(rule.allowedAncestorTeamIDs.joined(separator: ", "))")
        }
        if !rule.allowedAncestorSigningIDs.isEmpty {
            criteria.append("ancestor signing IDs: \(rule.allowedAncestorSigningIDs.joined(separator: ", "))")
        }
        return .denied(ruleID: rule.id, rule: rule.protectedPathPrefix, allowedCriteria: criteria.joined(separator: "; "))
    }
    return .noRuleApplies
}
