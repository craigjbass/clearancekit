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

// MARK: - Evaluated processes

public struct ProcessFacts: Equatable, Sendable {
    public let processPath: String
    public let teamID: String
    public let signingID: String

    public init(processPath: String, teamID: String, signingID: String) {
        self.processPath = processPath
        self.teamID = teamID
        self.signingID = signingID
    }
}

public enum ResponsibleProcess: Equatable, Sendable {
    case known(ProcessFacts)
    case unknown
}

public enum CheckedProcess: Equatable, Sendable {
    case itself
    case responsible(ProcessFacts)
    case unknownResponsible
}

public enum IdentifiedProcess: Equatable, Sendable {
    case itself
    case responsible(ProcessFacts)

    public var checkedProcess: CheckedProcess {
        switch self {
        case .itself: return .itself
        case .responsible(let facts): return .responsible(facts)
        }
    }
}

public struct PolicySubject: Sendable {
    public let process: ProcessFacts
    public let ancestors: [AncestorInfo]
    public let responsibleProcess: ResponsibleProcess
    public let responsibleAncestors: [AncestorInfo]

    public init(
        process: ProcessFacts,
        ancestors: [AncestorInfo],
        responsibleProcess: ResponsibleProcess,
        responsibleAncestors: [AncestorInfo]
    ) {
        self.process = process
        self.ancestors = ancestors
        self.responsibleProcess = responsibleProcess
        self.responsibleAncestors = responsibleAncestors
    }
}

// MARK: - PolicyDecision

public enum PolicyDecision {
    /// Process is on the global allowlist — bypasses all rules.
    case globallyAllowed
    /// Path not covered by any rule — default allow.
    case noRuleApplies
    /// Covered by a rule and a specific criterion matched.
    case allowed(ruleID: UUID, ruleName: String, ruleSource: RuleSource, matchedCriterion: String, checkedProcess: CheckedProcess)
    /// Covered by a rule but no criterion matched — denied.
    case denied(ruleID: UUID, ruleName: String, ruleSource: RuleSource, allowedCriteria: String, checkedProcess: CheckedProcess)
    /// Jailed process accessed a path within its allowed prefixes.
    case jailAllowed(ruleID: UUID, ruleName: String, matchedPrefix: String)
    /// Jailed process accessed a path outside its allowed prefixes — denied.
    case jailDenied(ruleID: UUID, ruleName: String, allowedPrefixes: [String])
    /// Covered by a rule that allows access only after Touch ID authorization.
    /// The filter must drive the GUI prompt and either open a session or deny.
    case requiresAuthorization(
        ruleID: UUID,
        ruleName: String,
        ruleSource: RuleSource,
        criterion: String,
        sessionDuration: TimeInterval,
        checkedProcess: IdentifiedProcess
    )

    public var isAllowed: Bool {
        switch self {
        case .denied, .jailDenied, .requiresAuthorization: return false
        default: return true
        }
    }

    public var matchedRuleID: UUID? {
        switch self {
        case .allowed(let ruleID, _, _, _, _): return ruleID
        case .denied(let ruleID, _, _, _, _): return ruleID
        case .jailAllowed(let ruleID, _, _): return ruleID
        case .jailDenied(let ruleID, _, _): return ruleID
        case .requiresAuthorization(let ruleID, _, _, _, _, _): return ruleID
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
        case .allowed(_, let name, _, _, _): return name
        case .denied(_, let name, _, _, _): return name
        case .jailAllowed(_, let name, _): return name
        case .jailDenied(_, let name, _): return name
        case .requiresAuthorization(_, let name, _, _, _, _): return name
        default: return ""
        }
    }

    public var policySource: RuleSource? {
        switch self {
        case .allowed(_, _, let source, _, _): return source
        case .denied(_, _, let source, _, _): return source
        case .requiresAuthorization(_, _, let source, _, _, _): return source
        default: return nil
        }
    }

    public var checkedProcess: CheckedProcess {
        switch self {
        case .allowed(_, _, _, _, let checkedProcess): return checkedProcess
        case .denied(_, _, _, _, let checkedProcess): return checkedProcess
        case .requiresAuthorization(_, _, _, _, _, let identifiedProcess): return identifiedProcess.checkedProcess
        case .globallyAllowed, .noRuleApplies, .jailAllowed, .jailDenied: return .itself
        }
    }

    public var reason: String {
        switch self {
        case .globallyAllowed:
            return "Globally allowed"
        case .noRuleApplies:
            return "No rule applies — default allow"
        case .allowed(_, _, _, let criterion, _):
            return "Allowed: matched \(criterion)"
        case .denied(_, let ruleName, _, let criteria, _):
            return "Denied by rule \"\(ruleName)\" — allowed: \(criteria)"
        case .jailAllowed(_, let ruleName, let prefix):
            return "Jail \"\(ruleName)\" — allowed: matched prefix \(prefix)"
        case .jailDenied(_, let ruleName, let prefixes):
            return "Denied by jail \"\(ruleName)\" — allowed prefixes: \(prefixes.joined(separator: ", "))"
        case .requiresAuthorization(_, let ruleName, _, let criterion, _, _):
            return "Requires Touch ID for rule \"\(ruleName)\" — matched \(criterion)"
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

// MARK: - DoubleStarParentMatching

// stopAtDoubleStar keeps the older behaviour for `**` rules: a directory
// below the `**` can be moved or copied without this rule's permission.
public enum DoubleStarParentMatching: String, Codable {
    case allNestedDirectories = "all_nested_directories"
    case stopAtDoubleStar = "stop_at_double_star"

    public static func implied(by pattern: String) -> DoubleStarParentMatching {
        patternContainsDoubleStarComponent(pattern) ? .stopAtDoubleStar : .allNestedDirectories
    }
}

public func patternContainsDoubleStarComponent(_ pattern: String) -> Bool {
    pattern.split(separator: "/", omittingEmptySubsequences: true).contains("**")
}

// MARK: - Responsible process checks

public let defaultResponsibleProcessChecks: [ProcessSignature] = [
    ProcessSignature(teamID: appleTeamID, signingID: "com.apple.WebKit.Networking"),
    ProcessSignature(teamID: appleTeamID, signingID: "com.apple.WebKit.WebContent"),
    ProcessSignature(teamID: appleTeamID, signingID: "com.apple.WebKit.GPU"),
]

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

    /// When true, processes with no real code signature (empty team ID, not a
    /// platform binary) are denied even if they match a wildcard allowedSignatures
    /// entry such as *:*.
    public let requireValidSigning: Bool

    public var authorizedSignatures: [ProcessSignature]
    public let requiresAuthorization: Bool
    public let authorizationSessionDuration: TimeInterval
    public let doubleStarParentMatching: DoubleStarParentMatching
    public var responsibleProcessChecks: [ProcessSignature]

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
        enforceOnWriteOnly: Bool = false,
        requireValidSigning: Bool = false,
        authorizedSignatures: [ProcessSignature] = [],
        requiresAuthorization: Bool = false,
        authorizationSessionDuration: TimeInterval = 300,
        doubleStarParentMatching: DoubleStarParentMatching = .allNestedDirectories,
        responsibleProcessChecks: [ProcessSignature] = defaultResponsibleProcessChecks
    ) {
        self.id = id
        self.protectedPathPrefix = protectedPathPrefix
        self.source = source
        self.allowedProcessPaths = allowedProcessPaths
        self.allowedSignatures = allowedSignatures
        self.allowedAncestorProcessPaths = allowedAncestorProcessPaths
        self.allowedAncestorSignatures = allowedAncestorSignatures
        self.enforceOnWriteOnly = enforceOnWriteOnly
        self.requireValidSigning = requireValidSigning
        self.authorizedSignatures = authorizedSignatures
        self.requiresAuthorization = requiresAuthorization
        self.authorizationSessionDuration = authorizationSessionDuration
        self.doubleStarParentMatching = doubleStarParentMatching
        self.responsibleProcessChecks = responsibleProcessChecks
    }

    private enum CodingKeys: String, CodingKey {
        case id, protectedPathPrefix, source, allowedProcessPaths, allowedSignatures,
             allowedAncestorProcessPaths, allowedAncestorSignatures,
             enforceOnWriteOnly, requireValidSigning,
             authorizedSignatures, requiresAuthorization, authorizationSessionDuration, doubleStarParentMatching,
             responsibleProcessChecks
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
        requireValidSigning = (try? c.decode(Bool.self, forKey: .requireValidSigning)) ?? false
        authorizedSignatures = (try? c.decode([ProcessSignature].self, forKey: .authorizedSignatures)) ?? []
        requiresAuthorization = (try? c.decode(Bool.self, forKey: .requiresAuthorization)) ?? false
        authorizationSessionDuration = (try? c.decode(TimeInterval.self, forKey: .authorizationSessionDuration)) ?? 300
        doubleStarParentMatching = try c.decodeIfPresent(DoubleStarParentMatching.self, forKey: .doubleStarParentMatching)
            ?? .implied(by: protectedPathPrefix)
        responsibleProcessChecks = try c.decodeIfPresent([ProcessSignature].self, forKey: .responsibleProcessChecks)
            ?? defaultResponsibleProcessChecks
    }

    /// Custom encoder that omits fields when they equal their defaults. This is
    /// load-bearing for `Database.canonicalRulesJSON` signature compatibility:
    /// existing user databases were signed by a build whose FAARule had fewer
    /// fields, so the only way the old signatures still verify after upgrade is
    /// for the canonical JSON of a default-valued rule to remain byte-identical
    /// to the shape it had when originally signed.
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
        if requireValidSigning {
            try c.encode(requireValidSigning, forKey: .requireValidSigning)
        }
        if !authorizedSignatures.isEmpty {
            try c.encode(authorizedSignatures, forKey: .authorizedSignatures)
        }
        if requiresAuthorization {
            try c.encode(requiresAuthorization, forKey: .requiresAuthorization)
        }
        if authorizationSessionDuration != 300 {
            try c.encode(authorizationSessionDuration, forKey: .authorizationSessionDuration)
        }
        if doubleStarParentMatching != .implied(by: protectedPathPrefix) {
            try c.encode(doubleStarParentMatching, forKey: .doubleStarParentMatching)
        }
        if responsibleProcessChecks != defaultResponsibleProcessChecks {
            try c.encode(responsibleProcessChecks, forKey: .responsibleProcessChecks)
        }
    }
}

extension FAARule {
    public func checksResponsibleProcess(of process: ProcessFacts) -> Bool {
        responsibleProcessChecks.contains { $0.matches(resolvedTeamID: process.teamID, signingID: process.signingID) }
    }

    public var usesDoubleStarCompatibilityMode: Bool {
        guard patternContainsDoubleStarComponent(protectedPathPrefix) else { return false }
        switch doubleStarParentMatching {
        case .allNestedDirectories: return false
        case .stopAtDoubleStar: return true
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

    // Protect PAM configuration. Writing to /etc/pam.d outside of system
    // software updates is a known persistence technique — malicious PAM modules
    // can intercept every authentication on the machine. Reads are unrestricted.
    FAARule(
        id: UUID(uuidString: "A5816D31-EF55-4B7C-AF20-689D7AC3EF1A")!,
        protectedPathPrefix: "/etc/pam.d",
        source: .builtin,
        allowedSignatures: [
            ProcessSignature(teamID: appleTeamID, signingID: "com.apple.installer"),
            ProcessSignature(teamID: appleTeamID, signingID: "com.apple.SoftwareUpdateAgent"),
            ProcessSignature(teamID: appleTeamID, signingID: "com.apple.mdmclient"),
            ProcessSignature(teamID: appleTeamID, signingID: "com.apple.packagekit"),
        ],
        enforceOnWriteOnly: true
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

public func pathContainsProtectedPaths(_ path: String, by pattern: String, matching: DoubleStarParentMatching) -> Bool {
    let pathParts = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
    let patternParts = pattern.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
    return componentsLeadIntoPattern(path: pathParts[...], pattern: patternParts[...], matching: matching)
}

private func componentsLeadIntoPattern(path: ArraySlice<String>, pattern: ArraySlice<String>, matching: DoubleStarParentMatching) -> Bool {
    guard let patternHead = pattern.first else { return false }
    guard let pathHead = path.first else { return true }
    if patternHead == "**" { return pathBelowDoubleStarCounts(matching) }
    guard globMatches(string: pathHead, pattern: patternHead) else { return false }
    return componentsLeadIntoPattern(path: path.dropFirst(), pattern: pattern.dropFirst(), matching: matching)
}

private func pathBelowDoubleStarCounts(_ matching: DoubleStarParentMatching) -> Bool {
    switch matching {
    case .allNestedDirectories: return true
    case .stopAtDoubleStar: return false
    }
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

private func pathSpecificity(_ pattern: String) -> Int {
    pattern.split(separator: "/", omittingEmptySubsequences: true).count
}

public enum OperationReach {
    case singlePath
    case subtree
}

// MARK: - Policy evaluation

private struct IdentifiedRuleSubject {
    let process: ProcessFacts
    let ancestors: [AncestorInfo]
    let identifiedProcess: IdentifiedProcess
}

private enum RuleSubject {
    case identified(IdentifiedRuleSubject)
    case unknownResponsible
}

private extension PolicySubject {
    func ruleSubject(for rule: FAARule) -> RuleSubject {
        guard rule.checksResponsibleProcess(of: process) else {
            return .identified(IdentifiedRuleSubject(process: process, ancestors: ancestors, identifiedProcess: .itself))
        }
        switch responsibleProcess {
        case .known(let responsibleFacts):
            return .identified(IdentifiedRuleSubject(process: responsibleFacts, ancestors: responsibleAncestors, identifiedProcess: .responsible(responsibleFacts)))
        case .unknown:
            return .unknownResponsible
        }
    }
}

public func checkFAAPolicy(
    rules: [FAARule],
    path: String,
    subject: PolicySubject,
    accessKind: AccessKind
) -> PolicyDecision {
    let matching = rules.enumerated().compactMap { index, rule -> (index: Int, rule: FAARule)? in
        guard pathIsProtected(path, by: rule.protectedPathPrefix) else { return nil }
        return (index, rule)
    }
    let sorted = matching.sorted { lhs, rhs in
        let lhsSpec = pathSpecificity(lhs.rule.protectedPathPrefix)
        let rhsSpec = pathSpecificity(rhs.rule.protectedPathPrefix)
        if lhsSpec != rhsSpec { return lhsSpec > rhsSpec }
        if lhs.rule.enforceOnWriteOnly != rhs.rule.enforceOnWriteOnly { return lhs.rule.enforceOnWriteOnly }
        return lhs.index < rhs.index
    }

    for (_, rule) in sorted {
        if let ruleDecision = decision(for: rule, subject: subject.ruleSubject(for: rule), accessKind: accessKind) {
            return ruleDecision
        }
    }
    return .noRuleApplies
}

private func decision(
    for rule: FAARule,
    subject: RuleSubject,
    accessKind: AccessKind
) -> PolicyDecision? {
    if rule.enforceOnWriteOnly && accessKind == .read { return nil }

    switch subject {
    case .unknownResponsible:
        return .denied(
            ruleID: rule.id,
            ruleName: rule.protectedPathPrefix,
            ruleSource: rule.source,
            allowedCriteria: "known responsible process required",
            checkedProcess: .unknownResponsible
        )
    case .identified(let identifiedSubject):
        return decision(for: rule, identifiedSubject: identifiedSubject)
    }
}

private func decision(
    for rule: FAARule,
    identifiedSubject subject: IdentifiedRuleSubject
) -> PolicyDecision {
    let processPath = subject.process.processPath
    let teamID = subject.process.teamID
    let signingID = subject.process.signingID
    let identifiedProcess = subject.identifiedProcess
    let checkedProcess = identifiedProcess.checkedProcess

    if rule.requireValidSigning && teamID.isEmpty {
        return .denied(
            ruleID: rule.id,
            ruleName: rule.protectedPathPrefix,
            ruleSource: rule.source,
            allowedCriteria: "valid code signature required",
            checkedProcess: checkedProcess
        )
    }

    if !rule.allowedProcessPaths.isEmpty && rule.allowedProcessPaths.contains(processPath) {
        return .allowed(ruleID: rule.id, ruleName: rule.protectedPathPrefix, ruleSource: rule.source, matchedCriterion: "process path \(processPath)", checkedProcess: checkedProcess)
    }

    if !rule.allowedSignatures.isEmpty,
       let match = rule.allowedSignatures.first(where: { $0.matches(resolvedTeamID: teamID, signingID: signingID) }) {
        return .allowed(ruleID: rule.id, ruleName: rule.protectedPathPrefix, ruleSource: rule.source, matchedCriterion: "identity \(match)", checkedProcess: checkedProcess)
    }

    if !rule.authorizedSignatures.isEmpty,
       rule.authorizedSignatures.contains(where: { $0.matches(resolvedTeamID: teamID, signingID: signingID) }) {
        return .requiresAuthorization(
            ruleID: rule.id,
            ruleName: rule.protectedPathPrefix,
            ruleSource: rule.source,
            criterion: "authorizedSignature",
            sessionDuration: rule.authorizationSessionDuration,
            checkedProcess: identifiedProcess
        )
    }

    if rule.requiresAuthorization && !teamID.isEmpty {
        return .requiresAuthorization(
            ruleID: rule.id,
            ruleName: rule.protectedPathPrefix,
            ruleSource: rule.source,
            criterion: "requiresAuthorization",
            sessionDuration: rule.authorizationSessionDuration,
            checkedProcess: identifiedProcess
        )
    }

    if !rule.allowedAncestorProcessPaths.isEmpty {
        if let match = subject.ancestors.first(where: { rule.allowedAncestorProcessPaths.contains($0.path) }) {
            return .allowed(ruleID: rule.id, ruleName: rule.protectedPathPrefix, ruleSource: rule.source, matchedCriterion: "ancestor process path \(match.path)", checkedProcess: checkedProcess)
        }
    }

    if !rule.allowedAncestorSignatures.isEmpty {
        for ancestor in subject.ancestors {
            if let match = rule.allowedAncestorSignatures.first(where: { $0.matches(resolvedTeamID: ancestor.teamID, signingID: ancestor.signingID) }) {
                return .allowed(ruleID: rule.id, ruleName: rule.protectedPathPrefix, ruleSource: rule.source, matchedCriterion: "ancestor identity \(match) (\(ancestor.path))", checkedProcess: checkedProcess)
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
    return .denied(ruleID: rule.id, ruleName: rule.protectedPathPrefix, ruleSource: rule.source, allowedCriteria: criteria.joined(separator: "; "), checkedProcess: checkedProcess)
}

private enum AncestryNeed {
    case processAncestors
    case responsibleAncestors
}

private func ancestryNeeds(rules: [FAARule], path: String, process: ProcessFacts, responsibleProcess: ResponsibleProcess) -> Set<AncestryNeed> {
    let protectingRulesThatNeedAncestry = rules.filter { pathIsProtected(path, by: $0.protectedPathPrefix) && $0.requiresAncestry }
    return Set(protectingRulesThatNeedAncestry.compactMap { rule in
        guard rule.checksResponsibleProcess(of: process) else { return .processAncestors }
        return responsibleAncestryNeed(for: responsibleProcess)
    })
}

private func responsibleAncestryNeed(for responsibleProcess: ResponsibleProcess) -> AncestryNeed? {
    switch responsibleProcess {
    case .known: return .responsibleAncestors
    case .unknown: return nil
    }
}

/// Evaluates FAA policy rules against a file-access request.
///
/// Ancestry data is fetched lazily. Each provider is called at most once, and only when a
/// protecting rule needs ancestry for the process that provider describes. Rules that can be
/// resolved by process path or code signature alone never trigger a provider.
public func checkFAAPolicy(
    rules: [FAARule],
    path: String,
    process: ProcessFacts,
    responsibleProcess: ResponsibleProcess,
    accessKind: AccessKind,
    ancestryProvider: @Sendable () async -> [AncestorInfo],
    responsibleAncestryProvider: @Sendable () async -> [AncestorInfo]
) async -> PolicyDecision {
    let needs = ancestryNeeds(rules: rules, path: path, process: process, responsibleProcess: responsibleProcess)
    let ancestors = needs.contains(.processAncestors) ? await ancestryProvider() : []
    let responsibleAncestors = needs.contains(.responsibleAncestors) ? await responsibleAncestryProvider() : []
    let subject = PolicySubject(
        process: process,
        ancestors: ancestors,
        responsibleProcess: responsibleProcess,
        responsibleAncestors: responsibleAncestors
    )
    return checkFAAPolicy(rules: rules, path: path, subject: subject, accessKind: accessKind)
}

public func checkFAAPolicy(
    rules: [FAARule],
    path: String,
    secondaryPath: String?,
    reach: OperationReach,
    subject: PolicySubject,
    accessKind: AccessKind
) -> PolicyDecision {
    let primaryDecision = checkFAAPolicy(rules: rules, path: path, reach: reach, subject: subject, accessKind: accessKind)
    guard let secondaryPath else { return primaryDecision }
    let secondaryDecision = checkFAAPolicy(rules: rules, path: secondaryPath, reach: reach, subject: subject, accessKind: accessKind)
    return moreRestrictiveDecision(primaryDecision, secondaryDecision)
}

private func checkFAAPolicy(
    rules: [FAARule],
    path: String,
    reach: OperationReach,
    subject: PolicySubject,
    accessKind: AccessKind
) -> PolicyDecision {
    let pathDecision = checkFAAPolicy(rules: rules, path: path, subject: subject, accessKind: accessKind)
    switch reach {
    case .singlePath:
        return pathDecision
    case .subtree:
        let rulesBeneathDecision = checkRulesBeneath(path, rules: rules, subject: subject)
        return moreRestrictiveDecision(pathDecision, rulesBeneathDecision)
    }
}

// Moving or copying a directory moves or copies everything inside it, so the
// operation is a write to every protected path beneath — the Santa model.
private func checkRulesBeneath(
    _ path: String,
    rules: [FAARule],
    subject: PolicySubject
) -> PolicyDecision {
    let decisions = rules
        .filter { pathContainsProtectedPaths(path, by: $0.protectedPathPrefix, matching: $0.doubleStarParentMatching) }
        .compactMap { decision(for: $0, subject: subject.ruleSubject(for: $0), accessKind: .write) }
    guard let firstDecision = decisions.first else { return .noRuleApplies }
    return decisions.dropFirst().reduce(firstDecision, moreRestrictiveDecision)
}

public func moreRestrictiveDecision(_ lhs: PolicyDecision, _ rhs: PolicyDecision) -> PolicyDecision {
    if lhs.isDenial { return lhs }
    if rhs.isDenial { return rhs }
    if !lhs.isAllowed { return lhs }
    if !rhs.isAllowed { return rhs }
    return lhs
}

private extension PolicyDecision {
    var isDenial: Bool {
        switch self {
        case .denied, .jailDenied: return true
        case .globallyAllowed, .noRuleApplies, .allowed, .jailAllowed, .requiresAuthorization: return false
        }
    }
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
    let matching = rules.filter { pathIsProtected(path, by: $0.protectedPathPrefix) }
    guard let first = matching.first else { return .noRuleApplies }
    if matching.contains(where: \.requiresAncestry) {
        return .ancestryRequired(matchingRule: first)
    }
    return .processLevelOnly(matchingRule: first)
}

public func classifyPaths(_ path: String, secondaryPath: String?, reach: OperationReach, rules: [FAARule]) -> PathRuleClassification {
    let primaryClassification = classifyPath(path, reach: reach, rules: rules)
    guard let secondaryPath else { return primaryClassification }
    let secondaryClassification = classifyPath(secondaryPath, reach: reach, rules: rules)
    return moreRestrictive(primaryClassification, secondaryClassification)
}

private func classifyPath(_ path: String, reach: OperationReach, rules: [FAARule]) -> PathRuleClassification {
    let matching = rules.filter { ruleApplies($0, to: path, reach: reach) }
    guard let first = matching.first else { return .noRuleApplies }
    if matching.contains(where: \.requiresAncestry) {
        return .ancestryRequired(matchingRule: first)
    }
    return .processLevelOnly(matchingRule: first)
}

private func ruleApplies(_ rule: FAARule, to path: String, reach: OperationReach) -> Bool {
    if pathIsProtected(path, by: rule.protectedPathPrefix) { return true }
    switch reach {
    case .singlePath: return false
    case .subtree: return pathContainsProtectedPaths(path, by: rule.protectedPathPrefix, matching: rule.doubleStarParentMatching)
    }
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
    reach: OperationReach,
    subject: PolicySubject,
    accessKind: AccessKind
) -> PolicyDecision {
    let process = subject.process
    if isGloballyAllowed(allowlist: allowlist, processPath: process.processPath, signingID: process.signingID, teamID: process.teamID) {
        return .globallyAllowed
    }

    if !ancestorAllowlist.isEmpty {
        if isGloballyAllowedByAncestry(ancestorAllowlist: ancestorAllowlist, ancestors: subject.ancestors) {
            return .globallyAllowed
        }
    }

    return checkFAAPolicy(rules: rules, path: path, secondaryPath: secondaryPath, reach: reach, subject: subject, accessKind: accessKind)
}

public func evaluateAccess(
    rules: [FAARule],
    allowlist: [AllowlistEntry],
    ancestorAllowlist: [AncestorAllowlistEntry] = [],
    path: String,
    process: ProcessFacts,
    responsibleProcess: ResponsibleProcess,
    accessKind: AccessKind,
    ancestryProvider: @Sendable () async -> [AncestorInfo],
    responsibleAncestryProvider: @Sendable () async -> [AncestorInfo]
) async -> PolicyDecision {
    if isGloballyAllowed(allowlist: allowlist, processPath: process.processPath, signingID: process.signingID, teamID: process.teamID) {
        return .globallyAllowed
    }

    let needs = ancestryNeeds(rules: rules, path: path, process: process, responsibleProcess: responsibleProcess)
    let needsProcessAncestors = !ancestorAllowlist.isEmpty || needs.contains(.processAncestors)
    let ancestors = needsProcessAncestors ? await ancestryProvider() : []
    let responsibleAncestors = needs.contains(.responsibleAncestors) ? await responsibleAncestryProvider() : []
    let subject = PolicySubject(
        process: process,
        ancestors: ancestors,
        responsibleProcess: responsibleProcess,
        responsibleAncestors: responsibleAncestors
    )

    return evaluateAccess(rules: rules, allowlist: allowlist, ancestorAllowlist: ancestorAllowlist, path: path, reach: .singlePath, subject: subject, accessKind: accessKind)
}
