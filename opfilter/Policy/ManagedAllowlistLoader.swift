//
//  ManagedAllowlistLoader.swift
//  opfilter
//
//  Reads the managed GlobalAllowlist preference delivered via MDM or a manually
//  installed .mobileconfig profile. Follows the same CFPreferencesCopyAppValue
//  pattern as ManagedPolicyLoader.
//
//  Plist / mobileconfig schema — entry in the GlobalAllowlist array:
//
//    ID             (string, optional)  — stable UUID string; omit to auto-derive
//    SigningID      (string)            — match by signing ID; OR
//    ProcessPath    (string)            — match by executable path
//    PlatformBinary (bool)              — if true, process must have empty team ID
//    TeamID         (string, optional)  — additional team constraint when !PlatformBinary
//

import Foundation

enum ManagedAllowlistLoader {
    private static let preferencesDomain: CFString = XPCConstants.bundleIDPrefix as CFString
    private static let allowlistKey: CFString = "GlobalAllowlist" as CFString

    static func load() -> [AllowlistEntry] {
        guard let raw = CFPreferencesCopyAppValue(allowlistKey, preferencesDomain) as? [[String: Any]] else {
            NSLog("ManagedAllowlistLoader: No managed GlobalAllowlist found — running without managed allowlist tier")
            return []
        }
        let entries = raw.compactMap(parseEntry)
        NSLog("ManagedAllowlistLoader: Loaded %d managed allowlist entry/entries", entries.count)
        return entries
    }

    static func loadWithSync() -> [AllowlistEntry] {
        CFPreferencesAppSynchronize(preferencesDomain)
        return load()
    }

    // MARK: - Private

    private static func parseEntry(_ dict: [String: Any]) -> AllowlistEntry? {
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
            id = deterministicID(for: signingID.isEmpty ? processPath : signingID)
        }

        return AllowlistEntry(
            id: id,
            signingID: signingID,
            processPath: processPath,
            platformBinary: platformBinary,
            teamID: teamID
        )
    }

    private static func deterministicID(for name: String) -> UUID {
        uuidV5(namespace: uuidV5URLNamespace, name: name)
    }
}
