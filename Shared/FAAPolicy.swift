//
//  FAAPolicy.swift
//  clearancekit
//
//  Created by Craig J. Bass on 16/02/2026.
//

import Foundation

// MARK: - PolicyDecision

public enum PolicyDecision {
    /// Path not covered by any rule — default allow.
    case noRuleApplies
    /// Covered by a rule and a specific criterion matched.
    case allowed(matchedCriterion: String)
    /// Covered by a rule but no criterion matched — denied.
    case denied(rule: String, allowedCriteria: String)

    public var isAllowed: Bool {
        if case .denied = self { return false }
        return true
    }

    public var reason: String {
        switch self {
        case .noRuleApplies:
            return "No rule applies — default allow"
        case .allowed(let criterion):
            return "Allowed: matched \(criterion)"
        case .denied(let rule, let criteria):
            return "Denied by rule \"\(rule)\" — allowed: \(criteria)"
        }
    }
}

// MARK: - FAARule

public struct FAARule {
    public let protectedPathPrefix: String
    public let allowedProcessPaths: [String]
    public let allowedTeamIDs: [String]
    public let allowedSigningIDs: [String]
    public let allowedAncestorProcessPaths: [String]
    public let allowedAncestorTeamIDs: [String]
    public let allowedAncestorSigningIDs: [String]

    public init(
        protectedPathPrefix: String,
        allowedProcessPaths: [String] = [],
        allowedTeamIDs: [String] = [],
        allowedSigningIDs: [String] = [],
        allowedAncestorProcessPaths: [String] = [],
        allowedAncestorTeamIDs: [String] = [],
        allowedAncestorSigningIDs: [String] = []
    ) {
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

public let faaPolicy: [FAARule] = [
    // Example: only Finder and Terminal may access secrets
    FAARule(
        protectedPathPrefix: "/opt/clearancekit/secrets",
        allowedProcessPaths: [
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
        ],
        allowedTeamIDs: [""],
        allowedAncestorSigningIDs: ["com.apple.Terminal"]
    ),
]

// MARK: - Policy evaluation

public func checkFAAPolicy(
    path: String,
    processPath: String,
    teamID: String,
    signingID: String,
    ancestors: [AncestorInfo] = []
) -> PolicyDecision {
    for rule in faaPolicy {
        guard path.hasPrefix(rule.protectedPathPrefix) else { continue }

        if !rule.allowedProcessPaths.isEmpty && rule.allowedProcessPaths.contains(processPath) {
            return .allowed(matchedCriterion: "process path \(processPath)")
        }

        // teamID and signingID are AND: both specified constraints must be satisfied.
        let teamOK    = rule.allowedTeamIDs.isEmpty    || rule.allowedTeamIDs.contains(teamID)
        let signingOK = rule.allowedSigningIDs.isEmpty || rule.allowedSigningIDs.contains(signingID)
        if (!rule.allowedTeamIDs.isEmpty || !rule.allowedSigningIDs.isEmpty) && teamOK && signingOK {
            var parts: [String] = []
            if !rule.allowedTeamIDs.isEmpty    { parts.append("team ID \(teamID)") }
            if !rule.allowedSigningIDs.isEmpty { parts.append("signing ID \(signingID)") }
            return .allowed(matchedCriterion: parts.joined(separator: " and "))
        }

        if !rule.allowedAncestorProcessPaths.isEmpty,
           let match = ancestors.first(where: { rule.allowedAncestorProcessPaths.contains($0.path) }) {
            return .allowed(matchedCriterion: "ancestor process path \(match.path)")
        }

        // Ancestor teamID and signingID are also AND across both constraints.
        for ancestor in ancestors {
            let aTeamOK    = rule.allowedAncestorTeamIDs.isEmpty    || rule.allowedAncestorTeamIDs.contains(ancestor.teamID)
            let aSigningOK = rule.allowedAncestorSigningIDs.isEmpty || rule.allowedAncestorSigningIDs.contains(ancestor.signingID)
            if (!rule.allowedAncestorTeamIDs.isEmpty || !rule.allowedAncestorSigningIDs.isEmpty) && aTeamOK && aSigningOK {
                var parts: [String] = []
                if !rule.allowedAncestorTeamIDs.isEmpty    { parts.append("ancestor team ID \(ancestor.teamID)") }
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
        return .denied(rule: rule.protectedPathPrefix, allowedCriteria: criteria.joined(separator: "; "))
    }
    return .noRuleApplies
}
