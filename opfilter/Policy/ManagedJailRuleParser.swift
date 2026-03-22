//
//  ManagedJailRuleParser.swift
//  opfilter
//
//  Parses a plist dictionary entry from the MDM-delivered JailRules array
//  into a JailRule. Separated from ManagedJailRuleLoader so the parsing
//  logic can be exercised directly in tests without a live CFPreferences layer.
//
//  Plist / mobileconfig schema — entry in the JailRules array:
//
//    ID                  (string, optional)  — stable UUID; omit to auto-derive from JailedSignature
//    Name                (string, required)  — display name shown in the GUI
//    JailedSignature     (string, required)  — "teamID:signingID" of the process to jail
//    AllowedPathPrefixes (array of strings)  — paths the jailed process may access
//

import Foundation

/// Converts a single plist dictionary from the managed JailRules array into
/// a JailRule. Returns nil when Name or JailedSignature are absent or malformed.
func parseManagedJailRule(_ dict: [String: Any]) -> JailRule? {
    let name = dict["Name"] as? String ?? ""
    guard !name.isEmpty else {
        NSLog("ManagedJailRuleLoader: Skipping entry with no Name")
        return nil
    }

    let signatureString = dict["JailedSignature"] as? String ?? ""
    guard let colonIndex = signatureString.firstIndex(of: ":") else {
        NSLog("ManagedJailRuleLoader: Skipping entry with invalid JailedSignature (missing colon): %@", signatureString)
        return nil
    }
    let team = String(signatureString[signatureString.startIndex..<colonIndex])
    let signing = String(signatureString[signatureString.index(after: colonIndex)...])
    guard !signing.isEmpty else {
        NSLog("ManagedJailRuleLoader: Skipping entry with empty signingID in JailedSignature: %@", signatureString)
        return nil
    }

    let effectiveTeam = team.isEmpty ? appleTeamID : team
    let jailedSignature = ProcessSignature(teamID: effectiveTeam, signingID: signing)

    let allowedPathPrefixes = dict["AllowedPathPrefixes"] as? [String] ?? []

    let id: UUID
    if let idString = dict["ID"] as? String, let parsed = UUID(uuidString: idString) {
        id = parsed
    } else {
        id = uuidV5(namespace: uuidV5URLNamespace, name: jailedSignature.description)
    }

    return JailRule(
        id: id,
        name: name,
        source: .mdm,
        jailedSignature: jailedSignature,
        allowedPathPrefixes: allowedPathPrefixes
    )
}
