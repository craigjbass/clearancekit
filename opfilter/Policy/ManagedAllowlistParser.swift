//
//  ManagedAllowlistParser.swift
//  opfilter
//
//  Parses a plist dictionary entry from the MDM-delivered GlobalAllowlist array
//  into an AllowlistEntry. Separated from ManagedAllowlistLoader so the parsing
//  logic can be exercised directly in tests without a live CFPreferences layer.
//

import Foundation

/// Converts a single plist dictionary from the managed GlobalAllowlist array into
/// an AllowlistEntry. Returns nil when both SigningID and ProcessPath are absent or empty.
func parseManagedAllowlistEntry(_ dict: [String: Any]) -> AllowlistEntry? {
    let signingID   = dict["SigningID"]   as? String ?? ""
    let processPath = dict["ProcessPath"] as? String ?? ""
    guard !signingID.isEmpty || !processPath.isEmpty else {
        NSLog("ManagedAllowlistLoader: Skipping entry with no SigningID or ProcessPath")
        return nil
    }

    let platformBinary = dict["PlatformBinary"] as? Bool ?? false
    let teamID = dict["TeamID"] as? String ?? ""

    let id: UUID
    if let idString = dict["ID"] as? String, let parsed = UUID(uuidString: idString) {
        id = parsed
    } else {
        id = uuidV5(namespace: uuidV5URLNamespace, name: signingID.isEmpty ? processPath : signingID)
    }

    return AllowlistEntry(
        id: id,
        signingID: signingID,
        processPath: processPath,
        platformBinary: platformBinary,
        teamID: teamID
    )
}
