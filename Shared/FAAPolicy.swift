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

// MARK: - ProcessSignature

/// A combined process identity in the form `teamID:signingID`.
/// Use `appleTeamID` ("apple") for Apple platform binaries.
/// Use `*` as the signingID to allow any signing ID from that team.
public struct ProcessSignature: Codable, Equatable, Hashable {
    public let teamID: String
    public let signingID: String

    public init(teamID: String, signingID: String) {
        self.teamID = teamID
        self.signingID = signingID
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)
        guard let colonIndex = string.firstIndex(of: ":") else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "ProcessSignature requires teamID:signingID format")
        }
        teamID = String(string[string.startIndex..<colonIndex])
        signingID = String(string[string.index(after: colonIndex)...])
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode("\(teamID):\(signingID)")
    }

    public func matches(resolvedTeamID: String, signingID: String) -> Bool {
        guard teamID == resolvedTeamID else { return false }
        return self.signingID == "*" || self.signingID == signingID
    }
}

extension ProcessSignature: CustomStringConvertible {
    public var description: String { "\(teamID):\(signingID)" }
}

// MARK: - FAARule

public struct FAARule: Identifiable, Codable, Equatable {
    public let id: UUID
    public let protectedPathPrefix: String

    /// The literal path prefix passed to `es_mute_path`.
    /// For wildcard patterns this is the last fully-literal directory component;
    /// the kernel delivers a superset of events which the policy filter narrows down.
    public var esMutePath: String { mutePath(for: protectedPathPrefix) }
    public let allowedProcessPaths: [String]
    public let allowedSignatures: [ProcessSignature]
    public let allowedAncestorProcessPaths: [String]
    public let allowedAncestorSignatures: [ProcessSignature]

    public init(
        id: UUID = UUID(),
        protectedPathPrefix: String,
        allowedProcessPaths: [String] = [],
        allowedSignatures: [ProcessSignature] = [],
        allowedAncestorProcessPaths: [String] = [],
        allowedAncestorSignatures: [ProcessSignature] = []
    ) {
        self.id = id
        self.protectedPathPrefix = protectedPathPrefix
        self.allowedProcessPaths = allowedProcessPaths
        self.allowedSignatures = allowedSignatures
        self.allowedAncestorProcessPaths = allowedAncestorProcessPaths
        self.allowedAncestorSignatures = allowedAncestorSignatures
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
        id: UUID(uuidString: "5DCEA92F-C4FB-4D5D-9E56-FD36D8F330DF")!,
        protectedPathPrefix: "/Library/Application Support/clearancekit",
        allowedSignatures: [ProcessSignature(teamID: clearancekitTeamID, signingID: "*")]
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

        // Apple platform binaries carry an empty team ID; resolve to appleTeamID for matching.
        let resolvedTeamID = teamID.isEmpty ? appleTeamID : teamID
        if !rule.allowedSignatures.isEmpty,
           let match = rule.allowedSignatures.first(where: { $0.matches(resolvedTeamID: resolvedTeamID, signingID: signingID) }) {
            return .allowed(matchedCriterion: "identity \(match)")
        }

        if !rule.allowedAncestorProcessPaths.isEmpty,
           let match = ancestors.first(where: { rule.allowedAncestorProcessPaths.contains($0.path) }) {
            return .allowed(matchedCriterion: "ancestor process path \(match.path)")
        }

        if !rule.allowedAncestorSignatures.isEmpty {
            for ancestor in ancestors {
                let resolvedAncestorTeamID = ancestor.teamID.isEmpty ? appleTeamID : ancestor.teamID
                if let match = rule.allowedAncestorSignatures.first(where: { $0.matches(resolvedTeamID: resolvedAncestorTeamID, signingID: ancestor.signingID) }) {
                    return .allowed(matchedCriterion: "ancestor identity \(match) (\(ancestor.path))")
                }
            }
        }

        var criteria: [String] = []
        if !rule.allowedProcessPaths.isEmpty {
            criteria.append("process paths: \(rule.allowedProcessPaths.joined(separator: ", "))")
        }
        if !rule.allowedSignatures.isEmpty {
            criteria.append("signatures: \(rule.allowedSignatures.map(\.description).joined(separator: ", "))")
        }
        if !rule.allowedAncestorProcessPaths.isEmpty {
            criteria.append("ancestor paths: \(rule.allowedAncestorProcessPaths.joined(separator: ", "))")
        }
        if !rule.allowedAncestorSignatures.isEmpty {
            criteria.append("ancestor signatures: \(rule.allowedAncestorSignatures.map(\.description).joined(separator: ", "))")
        }
        return .denied(ruleID: rule.id, rule: rule.protectedPathPrefix, allowedCriteria: criteria.joined(separator: "; "))
    }
    return .noRuleApplies
}
