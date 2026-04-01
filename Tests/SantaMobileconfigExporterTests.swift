//
//  SantaMobileconfigExporterTests.swift
//  clearancekit
//

import Testing
import Foundation

@Suite("SantaMobileconfigExporter")
struct SantaMobileconfigExporterTests {

    // MARK: - Helpers

    private func parsedProfile(from data: Data) throws -> [String: Any] {
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dict = plist as? [String: Any] else {
            Issue.record("Top-level plist is not a dictionary")
            throw ExportTestError.unexpectedShape
        }
        return dict
    }

    private func watchItems(from result: SantaMobileconfigExporter.ExportResult) throws -> [String: Any] {
        let profile = try parsedProfile(from: result.data)
        let payloadContent = profile["PayloadContent"] as? [[String: Any]] ?? []
        let santaPayload = payloadContent.first ?? [:]
        let fap = santaPayload["FileAccessPolicy"] as? [String: Any] ?? [:]
        return fap["WatchItems"] as? [String: Any] ?? [:]
    }

    private enum ExportTestError: Error { case unexpectedShape }

    // MARK: - Structure tests

    @Test("produces valid plist with required profile keys")
    func validProfileStructure() throws {
        let result = try SantaMobileconfigExporter.export(rules: [], allowlist: [])
        let profile = try parsedProfile(from: result.data)

        #expect(profile["PayloadType"] as? String == "Configuration")
        #expect(profile["PayloadVersion"] as? Int == 1)
        #expect(profile["PayloadScope"] as? String == "System")
        #expect(profile["PayloadContent"] != nil)
    }

    @Test("santa payload has FileAccessPolicy with v1.0 version")
    func fileAccessPolicyVersion() throws {
        let result = try SantaMobileconfigExporter.export(rules: [], allowlist: [])
        let profile = try parsedProfile(from: result.data)
        let payloadContent = profile["PayloadContent"] as? [[String: Any]] ?? []
        let santaPayload = payloadContent.first ?? [:]
        let fap = santaPayload["FileAccessPolicy"] as? [String: Any] ?? [:]

        #expect(santaPayload["PayloadType"] as? String == "com.northpolesec.santa")
        #expect(fap["Version"] as? String == "v1.0")
    }

    @Test("empty rules produces empty WatchItems")
    func emptyRulesProducesEmptyWatchItems() throws {
        let result = try SantaMobileconfigExporter.export(rules: [], allowlist: [])
        let items = try watchItems(from: result)

        #expect(items.isEmpty)
    }

    // MARK: - Watch item structure

    @Test("rule protected path appears in watch item Paths array")
    func rulePathAppearsInWatchItem() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Documents",
            allowedSignatures: [ProcessSignature(teamID: "TEAMID123", signingID: "com.example.app")]
        )
        let result = try SantaMobileconfigExporter.export(rules: [rule], allowlist: [])
        let items = try watchItems(from: result)

        let watchItem = items.values.first as? [String: Any]
        let paths = watchItem?["Paths"] as? [[String: Any]] ?? []

        #expect(paths.first?["Path"] as? String == "/Users/*/Documents")
        #expect(paths.first?["IsPrefix"] as? Bool == true)
    }

    @Test("watch item includes required Options keys")
    func watchItemOptionsKeys() throws {
        let rule = FAARule(
            protectedPathPrefix: "/etc/hosts",
            allowedProcessPaths: ["/bin/cat"]
        )
        let result = try SantaMobileconfigExporter.export(rules: [rule], allowlist: [])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let options = watchItem?["Options"] as? [String: Any] ?? [:]

        #expect(options["AllowReadAccess"] as? Bool == false)
        #expect(options["AuditOnly"] as? Bool == false)
        #expect(options["RuleType"] as? String == "PathsWithAllowedProcesses")
        #expect(options["BlockMessage"] != nil)
    }

    // MARK: - Process entries from rule signatures

    @Test("allowed signature with non-apple teamID maps to SigningID + TeamID")
    func thirdPartySignatureProcessEntry() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Library/ChromeData",
            allowedSignatures: [ProcessSignature(teamID: "EQHXZ8M8AV", signingID: "com.google.Chrome")]
        )
        let result = try SantaMobileconfigExporter.export(rules: [rule], allowlist: [])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let processes = watchItem?["Processes"] as? [[String: Any]] ?? []

        let chromeEntry = processes.first { $0["SigningID"] as? String == "com.google.Chrome" }
        #expect(chromeEntry != nil)
        #expect(chromeEntry?["TeamID"] as? String == "EQHXZ8M8AV")
        #expect(chromeEntry?["PlatformBinary"] == nil)
    }

    @Test("apple teamID signature maps to PlatformBinary true")
    func appleTeamIDMapsToplatformBinary() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Library/Cookies",
            allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.Safari")]
        )
        let result = try SantaMobileconfigExporter.export(rules: [rule], allowlist: [])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let processes = watchItem?["Processes"] as? [[String: Any]] ?? []

        let safariEntry = processes.first { $0["SigningID"] as? String == "com.apple.Safari" }
        #expect(safariEntry != nil)
        #expect(safariEntry?["PlatformBinary"] as? Bool == true)
        #expect(safariEntry?["TeamID"] == nil)
    }

    @Test("allowed process path maps to BinaryPath entry")
    func processPathMapsToBinaryPath() throws {
        let rule = FAARule(
            protectedPathPrefix: "/etc/ssh",
            allowedProcessPaths: ["/usr/bin/ssh"]
        )
        let result = try SantaMobileconfigExporter.export(rules: [rule], allowlist: [])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let processes = watchItem?["Processes"] as? [[String: Any]] ?? []

        let sshEntry = processes.first { $0["BinaryPath"] as? String == "/usr/bin/ssh" }
        #expect(sshEntry != nil)
    }

    // MARK: - Baseline allowlist inlining

    @Test("allowlist signingID entry appears in every watch item Processes")
    func allowlistEntryInlinedIntoWatchItem() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Documents",
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let allowlistEntry = AllowlistEntry(signingID: "com.apple.mdworker", platformBinary: true)

        let result = try SantaMobileconfigExporter.export(rules: [rule], allowlist: [allowlistEntry])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let processes = watchItem?["Processes"] as? [[String: Any]] ?? []

        let mdworkerEntry = processes.first { $0["SigningID"] as? String == "com.apple.mdworker" }
        #expect(mdworkerEntry != nil)
        #expect(mdworkerEntry?["PlatformBinary"] as? Bool == true)
    }

    @Test("allowlist processPath entry appears as BinaryPath in watch item Processes")
    func allowlistProcessPathInlinedAsBinaryPath() throws {
        let rule = FAARule(
            protectedPathPrefix: "/etc/ssh",
            allowedProcessPaths: ["/usr/bin/ssh"]
        )
        let allowlistEntry = AllowlistEntry(processPath: "/usr/local/bin/tool", platformBinary: true)

        let result = try SantaMobileconfigExporter.export(rules: [rule], allowlist: [allowlistEntry])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let processes = watchItem?["Processes"] as? [[String: Any]] ?? []

        let toolEntry = processes.first { $0["BinaryPath"] as? String == "/usr/local/bin/tool" }
        #expect(toolEntry != nil)
    }

    @Test("allowlist entries appear in all watch items when multiple rules exported")
    func allowlistAppearsInAllWatchItems() throws {
        let rules = [
            FAARule(protectedPathPrefix: "/Users/*/Documents"),
            FAARule(protectedPathPrefix: "/Users/*/Library"),
        ]
        let allowlistEntry = AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)

        let result = try SantaMobileconfigExporter.export(rules: rules, allowlist: [allowlistEntry])
        let items = try watchItems(from: result)

        #expect(items.count == 2)
        for (_, value) in items {
            let watchItem = value as? [String: Any]
            let processes = watchItem?["Processes"] as? [[String: Any]] ?? []
            let finderEntry = processes.first { $0["SigningID"] as? String == "com.apple.finder" }
            #expect(finderEntry != nil)
        }
    }

    // MARK: - Ancestry rules warning

    @Test("hasAncestryRules is false when no rules have ancestor criteria")
    func noAncestryRulesFlag() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Documents",
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let result = try SantaMobileconfigExporter.export(rules: [rule], allowlist: [])

        #expect(result.hasAncestryRules == false)
    }

    @Test("hasAncestryRules is true when a rule has allowedAncestorProcessPaths")
    func ancestorProcessPathsSetsFlag() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Documents",
            allowedAncestorProcessPaths: ["/usr/bin/sh"]
        )
        let result = try SantaMobileconfigExporter.export(rules: [rule], allowlist: [])

        #expect(result.hasAncestryRules == true)
    }

    @Test("hasAncestryRules is true when a rule has allowedAncestorSignatures")
    func ancestorSignaturesSetsFlag() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Documents",
            allowedAncestorSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.terminal")]
        )
        let result = try SantaMobileconfigExporter.export(rules: [rule], allowlist: [])

        #expect(result.hasAncestryRules == true)
    }

    @Test("ancestor criteria are not included as Processes in the watch item")
    func ancestorCriteriaDroppedFromProcesses() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Documents",
            allowedAncestorProcessPaths: ["/usr/bin/sh"],
            allowedAncestorSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.terminal")]
        )
        let result = try SantaMobileconfigExporter.export(rules: [rule], allowlist: [])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let processes = watchItem?["Processes"] as? [[String: Any]] ?? []

        let shEntry = processes.first { $0["BinaryPath"] as? String == "/usr/bin/sh" }
        let termEntry = processes.first { $0["SigningID"] as? String == "com.example.terminal" }
        #expect(shEntry == nil)
        #expect(termEntry == nil)
    }

    // MARK: - Jail rules subprocess warning

    @Test("hasJailRules is false when no jail rules are exported")
    func noJailRulesFlag() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Documents",
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let result = try SantaMobileconfigExporter.export(rules: [rule], allowlist: [])

        #expect(result.hasJailRules == false)
    }

    @Test("hasJailRules is true when jail rules are exported")
    func jailRulesSetsFlag() throws {
        let jailRule = JailRule(
            name: "Slack",
            jailedSignature: ProcessSignature(teamID: "BQR82RBBHL", signingID: "com.tinyspeck.slackmacgap"),
            allowedPathPrefixes: ["/tmp/**"]
        )
        let result = try SantaMobileconfigExporter.export(rules: [], jailRules: [jailRule], allowlist: [])

        #expect(result.hasJailRules == true)
    }

    // MARK: - Jail rule export

    @Test("jail rule produces watch item with ProcessesWithAllowedPaths rule type")
    func jailRuleUsesProcessesWithAllowedPaths() throws {
        let jailRule = JailRule(
            name: "Slack",
            jailedSignature: ProcessSignature(teamID: "BQR82RBBHL", signingID: "com.tinyspeck.slackmacgap"),
            allowedPathPrefixes: ["/Users/*/Library/Application Support/Slack/**"]
        )
        let result = try SantaMobileconfigExporter.export(rules: [], jailRules: [jailRule], allowlist: [])
        let items = try watchItems(from: result)

        let watchItem = items.values.first as? [String: Any]
        let options = watchItem?["Options"] as? [String: Any] ?? [:]

        #expect(options["RuleType"] as? String == "ProcessesWithAllowedPaths")
    }

    @Test("jail rule process signature appears in Processes array")
    func jailRuleProcessSignature() throws {
        let jailRule = JailRule(
            name: "Slack",
            jailedSignature: ProcessSignature(teamID: "BQR82RBBHL", signingID: "com.tinyspeck.slackmacgap"),
            allowedPathPrefixes: ["/tmp/**"]
        )
        let result = try SantaMobileconfigExporter.export(rules: [], jailRules: [jailRule], allowlist: [])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let processes = watchItem?["Processes"] as? [[String: Any]] ?? []

        let slackEntry = processes.first { $0["SigningID"] as? String == "com.tinyspeck.slackmacgap" }
        #expect(slackEntry != nil)
        #expect(slackEntry?["TeamID"] as? String == "BQR82RBBHL")
    }

    @Test("jail rule apple platform binary uses PlatformBinary flag")
    func jailRuleApplePlatformBinary() throws {
        let jailRule = JailRule(
            name: "Safari",
            jailedSignature: ProcessSignature(teamID: appleTeamID, signingID: "com.apple.Safari"),
            allowedPathPrefixes: ["/Users/*/Library/Safari/**"]
        )
        let result = try SantaMobileconfigExporter.export(rules: [], jailRules: [jailRule], allowlist: [])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let processes = watchItem?["Processes"] as? [[String: Any]] ?? []

        let safariEntry = processes.first { $0["SigningID"] as? String == "com.apple.Safari" }
        #expect(safariEntry?["PlatformBinary"] as? Bool == true)
        #expect(safariEntry?["TeamID"] == nil)
    }

    @Test("jail rule allowed path prefixes appear as Paths with double-star suffix stripped")
    func jailRuleAllowedPaths() throws {
        let jailRule = JailRule(
            name: "Slack",
            jailedSignature: ProcessSignature(teamID: "BQR82RBBHL", signingID: "com.tinyspeck.slackmacgap"),
            allowedPathPrefixes: ["/Users/*/Library/Application Support/Slack/**", "/tmp/**"]
        )
        let result = try SantaMobileconfigExporter.export(rules: [], jailRules: [jailRule], allowlist: [])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let paths = watchItem?["Paths"] as? [[String: Any]] ?? []

        let sortedPaths = paths.compactMap { $0["Path"] as? String }.sorted()
        #expect(sortedPaths == ["/Users/*/Library/Application Support/Slack", "/tmp"])
        #expect(paths.allSatisfy { $0["IsPrefix"] as? Bool == true })
    }

    @Test("jail rule path without double-star suffix uses exact match")
    func jailRuleExactPath() throws {
        let jailRule = JailRule(
            name: "Test",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.app"),
            allowedPathPrefixes: ["/etc/hosts"]
        )
        let result = try SantaMobileconfigExporter.export(rules: [], jailRules: [jailRule], allowlist: [])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let paths = watchItem?["Paths"] as? [[String: Any]] ?? []

        #expect(paths.first?["Path"] as? String == "/etc/hosts")
        #expect(paths.first?["IsPrefix"] as? Bool == false)
    }

    @Test("jail rules and FAA rules coexist in same WatchItems")
    func jailAndFAARulesCoexist() throws {
        let faaRule = FAARule(
            protectedPathPrefix: "/Users/*/Documents",
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let jailRule = JailRule(
            name: "Slack",
            jailedSignature: ProcessSignature(teamID: "BQR82RBBHL", signingID: "com.tinyspeck.slackmacgap"),
            allowedPathPrefixes: ["/tmp/**"]
        )
        let result = try SantaMobileconfigExporter.export(rules: [faaRule], jailRules: [jailRule], allowlist: [])
        let items = try watchItems(from: result)

        #expect(items.count == 2)

        let ruleTypes = items.values.compactMap { ($0 as? [String: Any])?["Options"] as? [String: Any] }
            .compactMap { $0["RuleType"] as? String }
        #expect(ruleTypes.contains("PathsWithAllowedProcesses"))
        #expect(ruleTypes.contains("ProcessesWithAllowedPaths"))
    }

    @Test("jail rule watch item key is derived from rule name")
    func jailRuleWatchItemKey() throws {
        let jailRule = JailRule(
            name: "Slack",
            jailedSignature: ProcessSignature(teamID: "BQR82RBBHL", signingID: "com.tinyspeck.slackmacgap"),
            allowedPathPrefixes: ["/tmp/**"]
        )
        let result = try SantaMobileconfigExporter.export(rules: [], jailRules: [jailRule], allowlist: [])
        let items = try watchItems(from: result)

        let key = items.keys.first
        #expect(key?.contains("Slack") == true)
    }

    @Test("baseline allowlist is not inlined into jail rule watch items")
    func allowlistNotInlinedIntoJailRules() throws {
        let jailRule = JailRule(
            name: "Slack",
            jailedSignature: ProcessSignature(teamID: "BQR82RBBHL", signingID: "com.tinyspeck.slackmacgap"),
            allowedPathPrefixes: ["/tmp/**"]
        )
        let allowlistEntry = AllowlistEntry(signingID: "com.apple.mdworker", platformBinary: true)
        let result = try SantaMobileconfigExporter.export(rules: [], jailRules: [jailRule], allowlist: [allowlistEntry])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let processes = watchItem?["Processes"] as? [[String: Any]] ?? []

        #expect(processes.count == 1)
        #expect(processes.first?["SigningID"] as? String == "com.tinyspeck.slackmacgap")
    }

    @Test("default baseline allowlist does not leak into jail rule Processes")
    func defaultBaselineAllowlistExcludedFromJailRules() throws {
        let jailRule = JailRule(
            name: "Slack",
            jailedSignature: ProcessSignature(teamID: "BQR82RBBHL", signingID: "com.tinyspeck.slackmacgap"),
            allowedPathPrefixes: ["/tmp/**"]
        )
        let result = try SantaMobileconfigExporter.export(rules: [], jailRules: [jailRule])
        let items = try watchItems(from: result)
        let watchItem = items.values.first as? [String: Any]
        let processes = watchItem?["Processes"] as? [[String: Any]] ?? []

        #expect(processes.count == 1)
        #expect(processes.first?["SigningID"] as? String == "com.tinyspeck.slackmacgap")
    }

    @Test("allowlist inlined into FAA watch item but not jail watch item in mixed export")
    func allowlistOnlyInFAARulesWhenMixedWithJail() throws {
        let faaRule = FAARule(
            protectedPathPrefix: "/Users/*/Documents",
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let jailRule = JailRule(
            name: "Slack",
            jailedSignature: ProcessSignature(teamID: "BQR82RBBHL", signingID: "com.tinyspeck.slackmacgap"),
            allowedPathPrefixes: ["/tmp/**"]
        )
        let allowlistEntry = AllowlistEntry(signingID: "com.apple.mdworker", platformBinary: true)
        let result = try SantaMobileconfigExporter.export(
            rules: [faaRule],
            jailRules: [jailRule],
            allowlist: [allowlistEntry]
        )
        let items = try watchItems(from: result)

        for (_, value) in items {
            let item = value as? [String: Any] ?? [:]
            let options = item["Options"] as? [String: Any] ?? [:]
            let ruleType = options["RuleType"] as? String ?? ""
            let processes = item["Processes"] as? [[String: Any]] ?? []

            if ruleType == "ProcessesWithAllowedPaths" {
                let signingIDs = processes.compactMap { $0["SigningID"] as? String }
                #expect(!signingIDs.contains("com.apple.mdworker"))
                #expect(processes.count == 1)
            } else {
                let signingIDs = processes.compactMap { $0["SigningID"] as? String }
                #expect(signingIDs.contains("com.apple.mdworker"))
            }
        }
    }
}
