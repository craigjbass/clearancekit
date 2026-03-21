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
}
