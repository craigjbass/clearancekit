//
//  FAAPolicy.swift
//  clearancekit
//
//  Created by Craig J. Bass on 16/02/2026.
//

import Foundation

struct AncestorInfo {
    let path: String
    let teamID: String
    let signingID: String
}

struct FAARule {
    let protectedPathPrefix: String
    let allowedProcessPaths: [String]
    let allowedTeamIDs: [String]
    let allowedSigningIDs: [String]
    let allowedAncestorProcessPaths: [String]
    let allowedAncestorTeamIDs: [String]
    let allowedAncestorSigningIDs: [String]

    init(protectedPathPrefix: String,
         allowedProcessPaths: [String] = [],
         allowedTeamIDs: [String] = [],
         allowedSigningIDs: [String] = [],
         allowedAncestorProcessPaths: [String] = [],
         allowedAncestorTeamIDs: [String] = [],
         allowedAncestorSigningIDs: [String] = []) {
        self.protectedPathPrefix = protectedPathPrefix
        self.allowedProcessPaths = allowedProcessPaths
        self.allowedTeamIDs = allowedTeamIDs
        self.allowedSigningIDs = allowedSigningIDs
        self.allowedAncestorProcessPaths = allowedAncestorProcessPaths
        self.allowedAncestorTeamIDs = allowedAncestorTeamIDs
        self.allowedAncestorSigningIDs = allowedAncestorSigningIDs
    }
}

let faaPolicy: [FAARule] = [
    // Example: only Finder and Terminal may access secrets
    FAARule(
        protectedPathPrefix: "/opt/clearancekit/secrets",
        allowedProcessPaths: [
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
        ]
    ),
]

/// Returns `nil` if access is allowed, or a denial reason string if blocked.
func checkFAAPolicy(path: String, processPath: String, teamID: String, signingID: String, ancestors: [AncestorInfo] = []) -> String? {
    for rule in faaPolicy {
        if path.hasPrefix(rule.protectedPathPrefix) {
            if !rule.allowedProcessPaths.isEmpty && rule.allowedProcessPaths.contains(processPath) {
                return nil
            }
            if !rule.allowedTeamIDs.isEmpty && rule.allowedTeamIDs.contains(teamID) {
                return nil
            }
            if !rule.allowedSigningIDs.isEmpty && rule.allowedSigningIDs.contains(signingID) {
                return nil
            }
            if !rule.allowedAncestorProcessPaths.isEmpty && ancestors.contains(where: { rule.allowedAncestorProcessPaths.contains($0.path) }) {
                return nil
            }
            if !rule.allowedAncestorTeamIDs.isEmpty && ancestors.contains(where: { rule.allowedAncestorTeamIDs.contains($0.teamID) }) {
                return nil
            }
            if !rule.allowedAncestorSigningIDs.isEmpty && ancestors.contains(where: { rule.allowedAncestorSigningIDs.contains($0.signingID) }) {
                return nil
            }
            var criteria: [String] = []
            if !rule.allowedProcessPaths.isEmpty {
                criteria.append("paths: \(rule.allowedProcessPaths.joined(separator: ", "))")
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
            return "Protected by rule \"\(rule.protectedPathPrefix)\" — allowed: \(criteria.joined(separator: "; "))"
        }
    }
    // No rule matched — allow by default
    return nil
}
