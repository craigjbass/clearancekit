//
//  ManagedJailRuleLoader.swift
//  opfilter
//
//  Reads the managed JailRules preference delivered via MDM or a manually
//  installed .mobileconfig profile. Follows the same CFPreferencesCopyAppValue
//  pattern as ManagedPolicyLoader.
//
//  Plist / mobileconfig schema — entry in the JailRules array:
//
//    ID                  (string, optional)  — stable UUID string; omit to auto-derive
//    Name                (string, required)  — display name shown in the GUI
//    JailedSignature     (string, required)  — "teamID:signingID" of the jailed process
//    AllowedPathPrefixes (array of strings)  — paths the jailed process may access
//

import Foundation

enum ManagedJailRuleLoader {
    private static let preferencesDomain: CFString = XPCConstants.bundleIDPrefix as CFString
    private static let jailRulesKey: CFString = "JailRules" as CFString

    static func load() -> [JailRule] {
        guard let raw = CFPreferencesCopyAppValue(jailRulesKey, preferencesDomain) as? [[String: Any]] else {
            NSLog("ManagedJailRuleLoader: No managed JailRules found — running without managed jail tier")
            return []
        }
        let rules = raw.compactMap(parseManagedJailRule)
        NSLog("ManagedJailRuleLoader: Loaded %d managed jail rule(s)", rules.count)
        return rules
    }

    static func loadWithSync() -> [JailRule] {
        CFPreferencesAppSynchronize(preferencesDomain)
        return load()
    }
}
