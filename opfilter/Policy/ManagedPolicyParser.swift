//
//  ManagedPolicyParser.swift
//  opfilter
//
//  Parses a plist dictionary entry from the MDM-delivered FAAPolicy array into
//  an FAARule. Separated from ManagedPolicyLoader so the parsing logic can be
//  exercised directly in tests without a live CFPreferences layer.
//

import Foundation

/// Converts a single plist dictionary from the managed FAAPolicy array into an
/// FAARule. Returns nil when the required ProtectedPathPrefix key is absent or empty.
func parseManagedPolicyRule(_ dict: [String: Any]) -> FAARule? {
    guard let path = dict["ProtectedPathPrefix"] as? String, !path.isEmpty else {
        NSLog("ManagedPolicyLoader: Skipping rule with missing or empty ProtectedPathPrefix")
        return nil
    }

    let id: UUID
    if let idString = dict["ID"] as? String, let parsed = UUID(uuidString: idString) {
        id = parsed
    } else {
        id = uuidV5(namespace: uuidV5URLNamespace, name: path)
    }

    return FAARule(
        id: id,
        protectedPathPrefix: path,
        source: .mdm,
        allowedProcessPaths:         dict["AllowedProcessPaths"]         as? [String] ?? [],
        allowedSignatures:           parseSignatures(dict["AllowedSignatures"]         as? [String] ?? []),
        allowedAncestorProcessPaths: dict["AllowedAncestorProcessPaths"] as? [String] ?? [],
        allowedAncestorSignatures:   parseSignatures(dict["AllowedAncestorSignatures"] as? [String] ?? []),
        enforceOnWriteOnly:          dict["EnforceOnWriteOnly"] as? Bool ?? false,
        doubleStarParentMatching:    parseDoubleStarParentMatching(dict["DoubleStarParentMatching"], pattern: path),
        responsibleProcessChecks:    parseResponsibleProcessChecks(dict["ResponsibleProcessChecks"], pattern: path)
    )
}

private func parseResponsibleProcessChecks(_ value: Any?, pattern: String) -> [ProcessSignature] {
    guard let value else { return defaultResponsibleProcessChecks }
    guard let entries = value as? [String] else {
        NSLog("ManagedPolicyLoader: ResponsibleProcessChecks for %@ is not an array of strings — using the default list", pattern)
        return defaultResponsibleProcessChecks
    }
    return parseSignatures(entries)
}

// An unknown value gives the stricter matching, so a typo in a profile
// never opens the parent-directory bypass.
private func parseDoubleStarParentMatching(_ value: Any?, pattern: String) -> DoubleStarParentMatching {
    guard let value else { return .implied(by: pattern) }
    guard let name = value as? String, let matching = DoubleStarParentMatching(rawValue: name) else {
        NSLog("ManagedPolicyLoader: Unknown DoubleStarParentMatching value for %@ — using all_nested_directories", pattern)
        return .allNestedDirectories
    }
    return matching
}
