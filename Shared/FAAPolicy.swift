//
//  FAAPolicy.swift
//  clearancekit
//
//  Created by Craig J. Bass on 16/02/2026.
//

import Foundation

struct FAARule {
    let protectedPathPrefix: String
    let allowedProcessPaths: [String]
    let allowedTeamIDs: [String]
    let allowedSigningIDs: [String]

    init(protectedPathPrefix: String, allowedProcessPaths: [String] = [], allowedTeamIDs: [String] = [], allowedSigningIDs: [String] = []) {
        self.protectedPathPrefix = protectedPathPrefix
        self.allowedProcessPaths = allowedProcessPaths
        self.allowedTeamIDs = allowedTeamIDs
        self.allowedSigningIDs = allowedSigningIDs
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

func checkFAAPolicy(path: String, processPath: String, teamID: String, signingID: String) -> Bool {
    for rule in faaPolicy {
        if path.hasPrefix(rule.protectedPathPrefix) {
            if !rule.allowedProcessPaths.isEmpty && rule.allowedProcessPaths.contains(processPath) {
                return true
            }
            if !rule.allowedTeamIDs.isEmpty && rule.allowedTeamIDs.contains(teamID) {
                return true
            }
            if !rule.allowedSigningIDs.isEmpty && rule.allowedSigningIDs.contains(signingID) {
                return true
            }
            return false
        }
    }
    // No rule matched — allow by default
    return true
}
