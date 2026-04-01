//
//  ClearanceKitMobileconfigExporter.swift
//  clearancekit
//
//  Serialises selected policy, app protection, jail, and allowlist data into
//  a ClearanceKit-compatible MDM .mobileconfig profile.
//
//  The produced profile follows the com.apple.ManagedClient.preferences payload
//  type so cfprefsd writes the values to the uk.craigbass.clearancekit managed
//  preferences domain, where opfilter reads them via CFPreferences.
//

import Foundation

enum ClearanceKitMobileconfigExporter {

    static func export(
        rules: [FAARule],
        protections: [AppProtection],
        jailRules: [JailRule],
        allowlistEntries: [AllowlistEntry],
        ancestorAllowlistEntries: [AncestorAllowlistEntry] = []
    ) throws -> Data {
        var settings: [String: Any] = [:]

        if !rules.isEmpty {
            settings["FAAPolicy"] = rules.map(faaRuleDict)
        }
        if !protections.isEmpty {
            settings["AppProtections"] = protections.map(appProtectionDict)
        }
        if !jailRules.isEmpty {
            settings["JailRules"] = jailRules.map(jailRuleDict)
        }
        if !allowlistEntries.isEmpty {
            settings["GlobalAllowlist"] = allowlistEntries.map(allowlistEntryDict)
        }
        if !ancestorAllowlistEntries.isEmpty {
            settings["GlobalAncestorAllowlist"] = ancestorAllowlistEntries.map(ancestorAllowlistEntryDict)
        }

        let innerPayload: [String: Any] = [
            "PayloadType": "com.apple.ManagedClient.preferences",
            "PayloadDisplayName": "clearancekit Policy",
            "PayloadIdentifier": "uk.craigbass.clearancekit.managed-policy.preferences",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1,
            "PayloadContent": [
                "uk.craigbass.clearancekit": [
                    "Forced": [
                        ["mcx_preference_settings": settings]
                    ]
                ]
            ] as [String: Any],
        ]

        let profile: [String: Any] = [
            "PayloadContent": [innerPayload],
            "PayloadDescription": "ClearanceKit managed policy exported from the GUI",
            "PayloadDisplayName": "ClearanceKit Managed Policy",
            "PayloadIdentifier": "uk.craigbass.clearancekit.managed-policy",
            "PayloadOrganization": "",
            "PayloadScope": "System",
            "PayloadType": "Configuration",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1,
        ]

        return try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
    }

    // MARK: - Dict builders

    private static func faaRuleDict(_ rule: FAARule) -> [String: Any] {
        var dict: [String: Any] = [
            "ID": rule.id.uuidString,
            "ProtectedPathPrefix": rule.protectedPathPrefix,
        ]
        if !rule.allowedProcessPaths.isEmpty {
            dict["AllowedProcessPaths"] = rule.allowedProcessPaths
        }
        if !rule.allowedSignatures.isEmpty {
            dict["AllowedSignatures"] = rule.allowedSignatures.map { "\($0.teamID):\($0.signingID)" }
        }
        if !rule.allowedAncestorProcessPaths.isEmpty {
            dict["AllowedAncestorProcessPaths"] = rule.allowedAncestorProcessPaths
        }
        if !rule.allowedAncestorSignatures.isEmpty {
            dict["AllowedAncestorSignatures"] = rule.allowedAncestorSignatures.map { "\($0.teamID):\($0.signingID)" }
        }
        return dict
    }

    private static func appProtectionDict(_ protection: AppProtection) -> [String: Any] {
        var dict: [String: Any] = [
            "ID": protection.id.uuidString,
            "AppName": protection.appName,
            "RuleIDs": protection.ruleIDs.map(\.uuidString),
        ]
        if !protection.bundleID.isEmpty {
            dict["BundleID"] = protection.bundleID
        }
        return dict
    }

    private static func jailRuleDict(_ rule: JailRule) -> [String: Any] {
        var dict: [String: Any] = [
            "ID": rule.id.uuidString,
            "Name": rule.name,
            "JailedSignature": "\(rule.jailedSignature.teamID):\(rule.jailedSignature.signingID)",
        ]
        if !rule.allowedPathPrefixes.isEmpty {
            dict["AllowedPathPrefixes"] = rule.allowedPathPrefixes
        }
        return dict
    }

    private static func allowlistEntryDict(_ entry: AllowlistEntry) -> [String: Any] {
        var dict: [String: Any] = ["ID": entry.id.uuidString]
        if !entry.signingID.isEmpty  { dict["SigningID"]   = entry.signingID }
        if !entry.processPath.isEmpty { dict["ProcessPath"] = entry.processPath }
        if entry.platformBinary {
            dict["PlatformBinary"] = true
        } else if !entry.teamID.isEmpty {
            dict["TeamID"] = entry.teamID
        }
        return dict
    }

    private static func ancestorAllowlistEntryDict(_ entry: AncestorAllowlistEntry) -> [String: Any] {
        var dict: [String: Any] = ["ID": entry.id.uuidString]
        if !entry.signingID.isEmpty  { dict["SigningID"]   = entry.signingID }
        if !entry.processPath.isEmpty { dict["ProcessPath"] = entry.processPath }
        if entry.platformBinary {
            dict["PlatformBinary"] = true
        } else if !entry.teamID.isEmpty {
            dict["TeamID"] = entry.teamID
        }
        return dict
    }
}
