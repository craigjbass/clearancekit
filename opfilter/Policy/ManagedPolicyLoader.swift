//
//  ManagedPolicyLoader.swift
//  opfilter
//
//  Reads the managed FAAPolicy preference delivered via MDM or a manually
//  installed .mobileconfig profile. Uses CFPreferencesCopyAppValue which
//  reads the merged preferences layer including managed profiles. This is
//  safe because opfilter runs as root — all writable preference locations
//  (/var/root/Library/Preferences, /Library/Preferences,
//  /Library/Managed Preferences) are root-owned, so no unprivileged user
//  can shadow the managed value.
//
//  Plist / mobileconfig schema — entry in the FAAPolicy array:
//
//    ID                          (string, optional)  — stable UUID string;
//                                                       omit to auto-derive
//                                                       from ProtectedPathPrefix
//    ProtectedPathPrefix         (string, required)  — path or glob pattern
//    AllowedProcessPaths         (array of strings)
//    AllowedSignatures           (array of strings)  — each "teamID:signingID",
//                                                       e.g. "apple:com.apple.Safari"
//                                                       or "37KMK6XFTT:*"
//    AllowedAncestorProcessPaths (array of strings)
//    AllowedAncestorSignatures   (array of strings)  — same format as AllowedSignatures
//    EnforceOnWriteOnly          (bool, optional)    — when true, the rule
//                                                       only fires for write
//                                                       operations; reads
//                                                       fall through to the
//                                                       next rule
//    DoubleStarParentMatching    (string, optional)  — "all_nested_directories"
//                                                       or "stop_at_double_star".
//                                                       Omit to use
//                                                       stop_at_double_star for
//                                                       patterns with a **
//                                                       component and
//                                                       all_nested_directories
//                                                       for other patterns
//    ResponsibleProcessChecks    (array of strings, optional) — same format as
//                                                       AllowedSignatures. A
//                                                       process that matches an
//                                                       entry is checked as its
//                                                       responsible process.
//                                                       Omit to use the three
//                                                       Apple WebKit services.
//                                                       An empty array turns the
//                                                       checks off for the rule
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "managed-config")

enum ManagedPolicyLoader {
    private static let preferencesDomain: CFString = XPCConstants.bundleIDPrefix as CFString
    private static let policyKey: CFString          = "FAAPolicy" as CFString

    /// Reads the managed FAAPolicy from CFPreferences.
    /// Call `loadWithSync()` when you want to guarantee the cache is flushed first
    /// (e.g. on a user-triggered resync).
    static func load() -> [FAARule] {
        guard let raw = CFPreferencesCopyAppValue(policyKey, preferencesDomain) as? [[String: Any]] else {
            logger.info("ManagedPolicyLoader: No managed FAAPolicy found — running without managed tier")
            return []
        }
        let rules = raw.compactMap(parseManagedPolicyRule)
        logger.info("ManagedPolicyLoader: Loaded \(rules.count, privacy: .public) managed rule(s)")
        for rule in rules where allowRisk(for: rule) == .spotlightIndexer {
            logger.warning("ManagedPolicyLoader: Managed rule \(rule.id.uuidString, privacy: .public) allows a Spotlight indexer — any account can read its protected files through it")
        }
        return rules
    }

    /// Flushes the CFPreferences cache before reading so that a freshly
    /// delivered MDM payload is picked up without an opfilter restart.
    static func loadWithSync() -> [FAARule] {
        CFPreferencesAppSynchronize(preferencesDomain)
        return load()
    }

}
