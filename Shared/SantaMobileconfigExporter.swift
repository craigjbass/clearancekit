//
//  SantaMobileconfigExporter.swift
//  clearancekit
//
//  Converts ClearanceKit FAA policy rules to a Santa FileAccessPolicy
//  mobileconfig profile.
//
//  Limitations (reflected in the hasAncestryRules flag):
//    - Santa's FileAccessPolicy has no concept of ancestry-based process matching.
//      Rules that allow access based on ancestor process paths or signatures will
//      have those criteria silently dropped from the Santa output.
//    - Baseline allowlist entries are inlined into every watch item's Processes
//      array, since Santa has no equivalent global bypass list.
//

import Foundation

public struct SantaMobileconfigExporter {

    public struct ExportResult {
        /// XML plist data ready to be written to a `.mobileconfig` file.
        public let data: Data
        /// True when at least one exported rule relied on ancestor-based criteria
        /// that cannot be represented in Santa's FileAccessPolicy.
        public let hasAncestryRules: Bool
    }

    /// Converts FAA rules and a baseline allowlist into a Santa mobileconfig.
    ///
    /// - Parameters:
    ///   - rules:   The FAA rules to export.
    ///   - allowlist: Entries that should be permitted to access every protected
    ///     path. Pass `baselineAllowlist` (the default) to mirror the baseline
    ///     built-in to ClearanceKit.
    public static func export(
        rules: [FAARule],
        allowlist: [AllowlistEntry] = baselineAllowlist
    ) throws -> ExportResult {
        let hasAncestryRules = rules.contains { $0.requiresAncestry }

        let watchItems: [String: Any] = rules.reduce(into: [:]) { dict, rule in
            dict[watchItemKey(for: rule)] = watchItem(for: rule, allowlist: allowlist)
        }

        let fileAccessPolicy: [String: Any] = [
            "Version": "v1.0",
            "WatchItems": watchItems,
        ]

        let santaPayload: [String: Any] = [
            "FileAccessPolicy": fileAccessPolicy,
            "PayloadDisplayName": "Santa File Access Policy",
            "PayloadIdentifier": "com.northpolesec.santa",
            "PayloadType": "com.northpolesec.santa",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1,
        ]

        let profile: [String: Any] = [
            "PayloadContent": [santaPayload],
            "PayloadDescription": "Santa FileAccessPolicy exported from ClearanceKit",
            "PayloadDisplayName": "Santa File Access Policy",
            "PayloadIdentifier": "uk.craigbass.clearancekit.santa-export",
            "PayloadOrganization": "",
            "PayloadScope": "System",
            "PayloadType": "Configuration",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1,
        ]

        let data = try PropertyListSerialization.data(
            fromPropertyList: profile,
            format: .xml,
            options: 0
        )

        return ExportResult(data: data, hasAncestryRules: hasAncestryRules)
    }

    // MARK: - Watch item construction

    /// Maximum characters taken from the sanitized path in a watch item key.
    private static let watchItemKeyPathLimit = 48
    /// Characters taken from the rule UUID as a uniqueness suffix.
    private static let watchItemKeyUUIDSuffixLength = 8

    private static func watchItemKey(for rule: FAARule) -> String {
        let sanitized = rule.protectedPathPrefix
            .components(separatedBy: CharacterSet.alphanumerics.inverted)
            .filter { !$0.isEmpty }
            .joined(separator: "_")
        let shortened = String(sanitized.prefix(watchItemKeyPathLimit))
        let suffix = String(rule.id.uuidString.prefix(watchItemKeyUUIDSuffixLength))
        return shortened.isEmpty ? suffix : "\(shortened)_\(suffix)"
    }

    private static func watchItem(for rule: FAARule, allowlist: [AllowlistEntry]) -> [String: Any] {
        var processes: [[String: Any]] = []

        for signature in rule.allowedSignatures {
            processes.append(processEntry(from: signature))
        }

        for path in rule.allowedProcessPaths {
            processes.append(["BinaryPath": path])
        }

        for entry in allowlist {
            if let process = processEntry(from: entry) {
                processes.append(process)
            }
        }

        var item: [String: Any] = [
            "Paths": [["Path": rule.protectedPathPrefix, "IsPrefix": true]],
            "Options": [
                "AllowReadAccess": false,
                "AuditOnly": false,
                "RuleType": "PathsWithAllowedProcesses",
                "BlockMessage": "Access to this path is restricted by ClearanceKit policy",
            ] as [String: Any],
        ]

        if !processes.isEmpty {
            item["Processes"] = processes
        }

        return item
    }

    // MARK: - Process entry helpers

    private static func processEntry(from signature: ProcessSignature) -> [String: Any] {
        if signature.teamID == appleTeamID {
            return ["SigningID": signature.signingID, "PlatformBinary": true]
        }
        return ["SigningID": signature.signingID, "TeamID": signature.teamID]
    }

    private static func processEntry(from entry: AllowlistEntry) -> [String: Any]? {
        var dict: [String: Any] = [:]

        if !entry.signingID.isEmpty {
            dict["SigningID"] = entry.signingID
        } else if !entry.processPath.isEmpty {
            dict["BinaryPath"] = entry.processPath
        } else {
            return nil
        }

        if entry.platformBinary {
            dict["PlatformBinary"] = true
        } else if !entry.teamID.isEmpty {
            dict["TeamID"] = entry.teamID
        }

        return dict
    }
}
