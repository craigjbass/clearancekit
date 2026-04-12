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

/// Sentinel value displayed when a process has no resolvable code signature —
/// both teamID and signingID are empty.
public let invalidSignature = "<invalid>"

// MARK: - RuleSource

public enum RuleSource: String, Codable, Equatable {
    case builtin
    case user
    case mdm
}

// MARK: - PolicyDecision

public enum PolicyDecision {
    /// Process is on the global allowlist — bypasses all rules.
    case globallyAllowed
    /// Path not covered by any rule — default allow.
    case noRuleApplies
    /// Covered by a rule and a specific criterion matched.
    case allowed(ruleID: UUID, ruleName: String, ruleSource: RuleSource, matchedCriterion: String)
    /// Covered by a rule but no criterion matched — denied.
    case denied(ruleID: UUID, ruleName: String, ruleSource: RuleSource, allowedCriteria: String)
    /// Jailed process accessed a path within its allowed prefixes.
    case jailAllowed(ruleID: UUID, ruleName: String, matchedPrefix: String)
    /// Jailed process accessed a path outside its allowed prefixes — denied.
    case jailDenied(ruleID: UUID, ruleName: String, allowedPrefixes: [String])

    public var isAllowed: Bool {
        switch self {
        case .denied, .jailDenied: return false
        default: return true
        }
    }

    public var matchedRuleID: UUID? {
        switch self {
        case .allowed(let ruleID, _, _, _): return ruleID
        case .denied(let ruleID, _, _, _): return ruleID
        case .jailAllowed(let ruleID, _, _): return ruleID
        case .jailDenied(let ruleID, _, _): return ruleID
        default: return nil
        }
    }

    public var jailedRuleID: UUID? {
        switch self {
        case .jailAllowed(let ruleID, _, _): return ruleID
        case .jailDenied(let ruleID, _, _): return ruleID
        default: return nil
        }
    }

    public var policyName: String {
        switch self {
        case .allowed(_, let name, _, _): return name
        case .denied(_, let name, _, _): return name
        case .jailAllowed(_, let name, _): return name
        case .jailDenied(_, let name, _): return name
        default: return ""
        }
    }

    public var policySource: RuleSource? {
        switch self {
        case .allowed(_, _, let source, _): return source
        case .denied(_, _, let source, _): return source
        default: return nil
        }
    }

    public var reason: String {
        switch self {
        case .globallyAllowed:
            return "Globally allowed"
        case .noRuleApplies:
            return "No rule applies — default allow"
        case .allowed(_, _, _, let criterion):
            return "Allowed: matched \(criterion)"
        case .denied(_, let ruleName, _, let criteria):
            return "Denied by rule \"\(ruleName)\" — allowed: \(criteria)"
        case .jailAllowed(_, let ruleName, let prefix):
            return "Jail \"\(ruleName)\" — allowed: matched prefix \(prefix)"
        case .jailDenied(_, let ruleName, let prefixes):
            return "Denied by jail \"\(ruleName)\" — allowed prefixes: \(prefixes.joined(separator: ", "))"
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
        guard teamID == "*" || teamID == resolvedTeamID else { return false }
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
    public let source: RuleSource

    public let allowedProcessPaths: [String]
    public var allowedSignatures: [ProcessSignature]
    public let allowedAncestorProcessPaths: [String]
    public var allowedAncestorSignatures: [ProcessSignature]

    /// When true, the rule only fires for write operations. Read-only opens
    /// (and AUTH_READDIR) skip this rule and continue to the next match —
    /// any process may read files under the protected path.
    public let enforceOnWriteOnly: Bool

    public var requiresAncestry: Bool {
        !allowedAncestorProcessPaths.isEmpty || !allowedAncestorSignatures.isEmpty
    }

    public init(
        id: UUID = UUID(),
        protectedPathPrefix: String,
        source: RuleSource = .user,
        allowedProcessPaths: [String] = [],
        allowedSignatures: [ProcessSignature] = [],
        allowedAncestorProcessPaths: [String] = [],
        allowedAncestorSignatures: [ProcessSignature] = [],
        enforceOnWriteOnly: Bool = false
    ) {
        self.id = id
        self.protectedPathPrefix = protectedPathPrefix
        self.source = source
        self.allowedProcessPaths = allowedProcessPaths
        self.allowedSignatures = allowedSignatures
        self.allowedAncestorProcessPaths = allowedAncestorProcessPaths
        self.allowedAncestorSignatures = allowedAncestorSignatures
        self.enforceOnWriteOnly = enforceOnWriteOnly
    }

    private enum CodingKeys: String, CodingKey {
        case id, protectedPathPrefix, source, allowedProcessPaths, allowedSignatures, allowedAncestorProcessPaths, allowedAncestorSignatures, enforceOnWriteOnly
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        protectedPathPrefix = try c.decode(String.self, forKey: .protectedPathPrefix)
        source = (try? c.decode(RuleSource.self, forKey: .source)) ?? .user
        allowedProcessPaths = (try? c.decode([String].self, forKey: .allowedProcessPaths)) ?? []
        allowedSignatures = (try? c.decode([ProcessSignature].self, forKey: .allowedSignatures)) ?? []
        allowedAncestorProcessPaths = (try? c.decode([String].self, forKey: .allowedAncestorProcessPaths)) ?? []
        allowedAncestorSignatures = (try? c.decode([ProcessSignature].self, forKey: .allowedAncestorSignatures)) ?? []
        enforceOnWriteOnly = (try? c.decode(Bool.self, forKey: .enforceOnWriteOnly)) ?? false
    }

    /// Custom encoder that omits `enforceOnWriteOnly` when it equals the
    /// default (`false`). This is load-bearing for `Database.canonicalRulesJSON`
    /// signature compatibility: existing user databases were signed by a
    /// build whose FAARule had no such field, so the only way the old
    /// signatures still verify after upgrade is for the canonical JSON
    /// of a default-false rule to remain byte-identical to the v1 shape.
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(protectedPathPrefix, forKey: .protectedPathPrefix)
        try c.encode(source, forKey: .source)
        try c.encode(allowedProcessPaths, forKey: .allowedProcessPaths)
        try c.encode(allowedSignatures, forKey: .allowedSignatures)
        try c.encode(allowedAncestorProcessPaths, forKey: .allowedAncestorProcessPaths)
        try c.encode(allowedAncestorSignatures, forKey: .allowedAncestorSignatures)
        if enforceOnWriteOnly {
            try c.encode(enforceOnWriteOnly, forKey: .enforceOnWriteOnly)
        }
    }
}

// MARK: - Policy

public let clearancekitTeamID = "37KMK6XFTT"

public let faaPolicy: [FAARule] = [
    // Protect the policy storage directory. Only processes signed by the
    // clearancekit team may open files under this path — this covers opfilter
    // itself and the GUI app. Any other process (including
    // a compromised user process) is denied at the kernel level before it can
    // read or tamper with the stored rules.
    FAARule(
        id: UUID(uuidString: "5DCEA92F-C4FB-4D5D-9E56-FD36D8F330DF")!,
        protectedPathPrefix: "/Library/Application Support/clearancekit",
        source: .builtin,
        allowedSignatures: [ProcessSignature(teamID: clearancekitTeamID, signingID: "uk.craigbass.clearancekit.opfilter")]
    ),
]

// MARK: - Path matching

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

/// Evaluates FAA policy rules against a file-access request.
///
/// Ancestry data is fetched lazily via `ancestryProvider` — the closure is called at most once,
/// only when the first matching rule actually requires an ancestry check. Rules that can be
/// resolved by process path or code signature alone will never trigger the provider, so the
/// potentially expensive wait for the process tree is deferred until it is truly necessary.
public func checkFAAPolicy(
    rules: [FAARule],
    path: String,
    processPath: String,
    teamID: String,
    signingID: String,
    accessKind: AccessKind,
    ancestors: [AncestorInfo]
) -> PolicyDecision {
    for rule in rules {
        guard pathIsProtected(path, by: rule.protectedPathPrefix) else { continue }
        if rule.enforceOnWriteOnly && accessKind == .read { continue }

        if !rule.allowedProcessPaths.isEmpty && rule.allowedProcessPaths.contains(processPath) {
            return .allowed(ruleID: rule.id, ruleName: rule.protectedPathPrefix, ruleSource: rule.source, matchedCriterion: "process path \(processPath)")
        }

        let resolvedTeamID = teamID.isEmpty ? appleTeamID : teamID
        if !rule.allowedSignatures.isEmpty,
           let match = rule.allowedSignatures.first(where: { $0.matches(resolvedTeamID: resolvedTeamID, signingID: signingID) }) {
            return .allowed(ruleID: rule.id, ruleName: rule.protectedPathPrefix, ruleSource: rule.source, matchedCriterion: "identity \(match)")
        }

        if !rule.allowedAncestorProcessPaths.isEmpty {
            if let match = ancestors.first(where: { rule.allowedAncestorProcessPaths.contains($0.path) }) {
                return .allowed(ruleID: rule.id, ruleName: rule.protectedPathPrefix, ruleSource: rule.source, matchedCriterion: "ancestor process path \(match.path)")
            }
        }

        if !rule.allowedAncestorSignatures.isEmpty {
            for ancestor in ancestors {
                let resolvedAncestorTeamID = ancestor.teamID.isEmpty ? appleTeamID : ancestor.teamID
                if let match = rule.allowedAncestorSignatures.first(where: { $0.matches(resolvedTeamID: resolvedAncestorTeamID, signingID: ancestor.signingID) }) {
                    return .allowed(ruleID: rule.id, ruleName: rule.protectedPathPrefix, ruleSource: rule.source, matchedCriterion: "ancestor identity \(match) (\(ancestor.path))")
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
        return .denied(ruleID: rule.id, ruleName: rule.protectedPathPrefix, ruleSource: rule.source, allowedCriteria: criteria.joined(separator: "; "))
    }
    return .noRuleApplies
}

public func checkFAAPolicy(
    rules: [FAARule],
    path: String,
    processPath: String,
    teamID: String,
    signingID: String,
    accessKind: AccessKind,
    ancestryProvider: @Sendable () async -> [AncestorInfo] = { [] }
) async -> PolicyDecision {
    let needsAncestry = rules.contains { pathIsProtected(path, by: $0.protectedPathPrefix) && $0.requiresAncestry }
    let ancestors = needsAncestry ? await ancestryProvider() : []
    return checkFAAPolicy(rules: rules, path: path, processPath: processPath, teamID: teamID, signingID: signingID, accessKind: accessKind, ancestors: ancestors)
}

public func checkFAAPolicy(
    rules: [FAARule],
    path: String,
    secondaryPath: String?,
    processPath: String,
    teamID: String,
    signingID: String,
    accessKind: AccessKind,
    ancestors: [AncestorInfo]
) -> PolicyDecision {
    let primaryDecision = checkFAAPolicy(rules: rules, path: path, processPath: processPath, teamID: teamID, signingID: signingID, accessKind: accessKind, ancestors: ancestors)
    guard let secondaryPath else { return primaryDecision }
    let secondaryDecision = checkFAAPolicy(rules: rules, path: secondaryPath, processPath: processPath, teamID: teamID, signingID: signingID, accessKind: accessKind, ancestors: ancestors)
    return moreRestrictiveDecision(primaryDecision, secondaryDecision)
}

private func moreRestrictiveDecision(_ lhs: PolicyDecision, _ rhs: PolicyDecision) -> PolicyDecision {
    if !lhs.isAllowed { return lhs }
    if !rhs.isAllowed { return rhs }
    return lhs
}

// MARK: - Path classification

public enum PathRuleClassification {
    /// No rule covers this path — default allow, no dwelling needed.
    case noRuleApplies
    /// The matching rule has only process-level criteria — can evaluate immediately.
    case processLevelOnly(matchingRule: FAARule)
    /// The matching rule requires ancestry data — must dwell for process tree.
    case ancestryRequired(matchingRule: FAARule)
}

/// Classifies a file path against the rule set to determine whether ancestry
/// data is needed before evaluating access. Uses first-match-wins semantics,
/// matching `checkFAAPolicy`.
public func classifyPath(_ path: String, rules: [FAARule]) -> PathRuleClassification {
    guard let matchingRule = rules.first(where: { pathIsProtected(path, by: $0.protectedPathPrefix) }) else {
        return .noRuleApplies
    }
    return matchingRule.requiresAncestry ? .ancestryRequired(matchingRule: matchingRule) : .processLevelOnly(matchingRule: matchingRule)
}

public func classifyPaths(_ path: String, secondaryPath: String?, rules: [FAARule]) -> PathRuleClassification {
    let primaryClassification = classifyPath(path, rules: rules)
    guard let secondaryPath else { return primaryClassification }
    let secondaryClassification = classifyPath(secondaryPath, rules: rules)
    return moreRestrictive(primaryClassification, secondaryClassification)
}

private func moreRestrictive(_ lhs: PathRuleClassification, _ rhs: PathRuleClassification) -> PathRuleClassification {
    switch (lhs, rhs) {
    case (.ancestryRequired, _): return lhs
    case (_, .ancestryRequired): return rhs
    case (.processLevelOnly, _): return lhs
    case (_, .processLevelOnly): return rhs
    default: return .noRuleApplies
    }
}

// MARK: - Unified access evaluation

public func evaluateAccess(
    rules: [FAARule],
    allowlist: [AllowlistEntry],
    ancestorAllowlist: [AncestorAllowlistEntry] = [],
    path: String,
    secondaryPath: String? = nil,
    processPath: String,
    teamID: String,
    signingID: String,
    accessKind: AccessKind,
    ancestors: [AncestorInfo]
) -> PolicyDecision {
    if isGloballyAllowed(allowlist: allowlist, processPath: processPath, signingID: signingID, teamID: teamID) {
        return .globallyAllowed
    }

    if !ancestorAllowlist.isEmpty {
        if isGloballyAllowedByAncestry(ancestorAllowlist: ancestorAllowlist, ancestors: ancestors) {
            return .globallyAllowed
        }
    }

    return checkFAAPolicy(rules: rules, path: path, secondaryPath: secondaryPath, processPath: processPath, teamID: teamID, signingID: signingID, accessKind: accessKind, ancestors: ancestors)
}

public func evaluateAccess(
    rules: [FAARule],
    allowlist: [AllowlistEntry],
    ancestorAllowlist: [AncestorAllowlistEntry] = [],
    path: String,
    processPath: String,
    teamID: String,
    signingID: String,
    accessKind: AccessKind,
    ancestryProvider: @Sendable () async -> [AncestorInfo] = { [] }
) async -> PolicyDecision {
    if isGloballyAllowed(allowlist: allowlist, processPath: processPath, signingID: signingID, teamID: teamID) {
        return .globallyAllowed
    }

    let needsAncestors = !ancestorAllowlist.isEmpty ||
        rules.contains { pathIsProtected(path, by: $0.protectedPathPrefix) && $0.requiresAncestry }
    let ancestors = needsAncestors ? await ancestryProvider() : []

    return evaluateAccess(rules: rules, allowlist: allowlist, ancestorAllowlist: ancestorAllowlist, path: path, processPath: processPath, teamID: teamID, signingID: signingID, accessKind: accessKind, ancestors: ancestors)
}
