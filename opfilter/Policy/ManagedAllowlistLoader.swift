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
        let entries = raw.compactMap(parseManagedAllowlistEntry)
        NSLog("ManagedAllowlistLoader: Loaded %d managed allowlist entry/entries", entries.count)
        return entries
    }

    static func loadWithSync() -> [AllowlistEntry] {
        CFPreferencesAppSynchronize(preferencesDomain)
        return load()
    }
}
