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
        /// True when the export includes jail rules. Santa's ProcessesWithAllowedPaths
        /// applies only to the matched process itself — subprocesses are not confined.
        public let hasJailRules: Bool
    }

    public static func export(
        rules: [FAARule],
        allowlist: [AllowlistEntry] = baselineAllowlist
    ) throws -> ExportResult {
        try export(rules: rules, jailRules: [], allowlist: allowlist)
    }

    public static func export(
        rules: [FAARule],
        jailRules: [JailRule],
        allowlist: [AllowlistEntry] = baselineAllowlist
    ) throws -> ExportResult {
        let hasAncestryRules = rules.contains { $0.requiresAncestry }

        var watchItems: [String: Any] = rules.reduce(into: [:]) { dict, rule in
            dict[watchItemKey(for: rule)] = watchItem(for: rule, allowlist: allowlist)
        }

        for jailRule in jailRules {
            watchItems[jailWatchItemKey(for: jailRule)] = jailWatchItem(for: jailRule)
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

        return ExportResult(data: data, hasAncestryRules: hasAncestryRules, hasJailRules: !jailRules.isEmpty)
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

    // MARK: - Jail rule watch items

    private static func jailWatchItemKey(for rule: JailRule) -> String {
        let sanitized = rule.name
            .components(separatedBy: CharacterSet.alphanumerics.inverted)
            .filter { !$0.isEmpty }
            .joined(separator: "_")
        let shortened = String(sanitized.prefix(watchItemKeyPathLimit))
        let suffix = String(rule.id.uuidString.prefix(watchItemKeyUUIDSuffixLength))
        return shortened.isEmpty ? suffix : "\(shortened)_\(suffix)"
    }

    private static func jailWatchItem(for rule: JailRule) -> [String: Any] {
        let paths: [[String: Any]] = rule.allowedPathPrefixes.map { prefix in
            let (path, isPrefix) = santaPath(from: prefix)
            return ["Path": path, "IsPrefix": isPrefix]
        }

        return [
            "Paths": paths,
            "Processes": [processEntry(from: rule.jailedSignature)],
            "Options": [
                "AllowReadAccess": false,
                "AuditOnly": false,
                "RuleType": "ProcessesWithAllowedPaths",
                "BlockMessage": "Access outside allowed paths is restricted by ClearanceKit jail policy",
            ] as [String: Any],
        ]
    }

    private static func santaPath(from pattern: String) -> (path: String, isPrefix: Bool) {
        let segments = pattern.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        var converted: [String] = []
        var isPrefix = false

        for segment in segments {
            if segment == "**" {
                isPrefix = true
                break
            }
            converted.append(segment.replacingOccurrences(of: "***", with: "*"))
        }

        let path = "/" + converted.joined(separator: "/")
        return (path, isPrefix)
    }
}
