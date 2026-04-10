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
        enforceOnWriteOnly:          dict["EnforceOnWriteOnly"] as? Bool ?? false
    )
}
