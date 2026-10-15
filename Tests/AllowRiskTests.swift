//
//  AllowRiskTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("allowRisk")
struct AllowRiskTests {
    @Test("exact indexer signature is a risk", arguments: spotlightIndexerSigningIDs)
    func exactIndexerSignatureIsRisk(signingID: String) {
        #expect(allowRisk(for: ProcessSignature(teamID: appleTeamID, signingID: signingID)) == .spotlightIndexer)
    }

    @Test("apple wildcard signature is a risk")
    func appleWildcardSignatureIsRisk() {
        #expect(allowRisk(for: ProcessSignature(teamID: appleTeamID, signingID: "*")) == .spotlightIndexer)
    }

    @Test("full wildcard signature is a risk")
    func fullWildcardSignatureIsRisk() {
        #expect(allowRisk(for: ProcessSignature(teamID: "*", signingID: "*")) == .spotlightIndexer)
    }

    @Test("other Apple signature is not a risk")
    func otherAppleSignatureIsNotRisk() {
        #expect(allowRisk(for: ProcessSignature(teamID: appleTeamID, signingID: "com.apple.mds_stores")) == .noKnownRisk)
    }

    @Test("third-party team with an indexer signing ID is not a risk")
    func thirdPartyTeamIsNotRisk() {
        #expect(allowRisk(for: ProcessSignature(teamID: "TEAM123", signingID: "com.apple.mdworker")) == .noKnownRisk)
    }

    @Test("platform-binary allowlist entry for an indexer is a risk", arguments: spotlightIndexerSigningIDs)
    func platformBinaryAllowlistEntryIsRisk(signingID: String) {
        #expect(allowRisk(for: AllowlistEntry(signingID: signingID, platformBinary: true)) == .spotlightIndexer)
    }

    @Test("platform-binary wildcard allowlist entry is a risk")
    func platformBinaryWildcardAllowlistEntryIsRisk() {
        #expect(allowRisk(for: AllowlistEntry(signingID: "*", platformBinary: true)) == .spotlightIndexer)
    }

    @Test("allowlist entry with an indexer signing ID and no team is a risk")
    func anyTeamIndexerAllowlistEntryIsRisk() {
        #expect(allowRisk(for: AllowlistEntry(signingID: "com.apple.mds")) == .spotlightIndexer)
    }

    @Test("allowlist entry with an indexer signing ID and a third-party team is not a risk")
    func thirdPartyTeamAllowlistEntryIsNotRisk() {
        #expect(allowRisk(for: AllowlistEntry(signingID: "com.apple.mds", teamID: "TEAM123")) == .noKnownRisk)
    }

    @Test("path-only allowlist entry for an indexer binary is a risk")
    func pathOnlyAllowlistEntryIsRisk() {
        let entry = AllowlistEntry(processPath: "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared", platformBinary: true)

        #expect(allowRisk(for: entry) == .spotlightIndexer)
    }

    @Test("path-only ancestor allowlist entry for an indexer binary is a risk")
    func pathOnlyAncestorEntryForIndexerIsRisk() {
        #expect(allowRisk(for: AncestorAllowlistEntry(processPath: "/System/Library/PrivateFrameworks/Spotlight.framework/mds")) == .spotlightIndexer)
    }

    @Test("rule allowing an indexer binary by process path is a risk")
    func ruleWithIndexerProcessPathIsRisk() {
        let rule = FAARule(protectedPathPrefix: "/Users/*/Secrets", allowedProcessPaths: ["/usr/libexec/mdsync"])

        #expect(allowRisk(for: rule) == .spotlightIndexer)
    }

    @Test("rule allowing an indexer binary by ancestor process path is a risk")
    func ruleWithIndexerAncestorProcessPathIsRisk() {
        let rule = FAARule(protectedPathPrefix: "/Users/*/Secrets", allowedAncestorProcessPaths: ["/usr/libexec/mdworker"])

        #expect(allowRisk(for: rule) == .spotlightIndexer)
    }

    @Test("process paths that only resemble an indexer binary are not a risk", arguments: ["/usr/libexec/mds_stores", "/tmp/mdworker_shared_helper"])
    func lookalikePathIsNotRisk(path: String) {
        #expect(allowRisk(for: AllowlistEntry(processPath: path)) == .noKnownRisk)
        #expect(allowRisk(for: FAARule(protectedPathPrefix: "/Users/*/Secrets", allowedProcessPaths: [path])) == .noKnownRisk)
    }

    @Test("ancestor allowlist entry for an indexer is a risk")
    func ancestorAllowlistEntryIsRisk() {
        #expect(allowRisk(for: AncestorAllowlistEntry(signingID: "com.apple.mdworker_shared", platformBinary: true)) == .spotlightIndexer)
    }

    @Test("path-only ancestor allowlist entry for another binary is not a risk")
    func pathOnlyAncestorAllowlistEntryIsNotRisk() {
        #expect(allowRisk(for: AncestorAllowlistEntry(processPath: "/usr/bin/mdimport")) == .noKnownRisk)
    }

    @Test("rule with the risk only in allowedAncestorSignatures is a risk")
    func ruleWithAncestorRiskIsRisk() {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Secrets",
            allowedSignatures: [ProcessSignature(teamID: "TEAM123", signingID: "com.example.app")],
            allowedAncestorSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.mds")]
        )

        #expect(allowRisk(for: rule) == .spotlightIndexer)
    }

    @Test("rule with the risk only in authorizedSignatures is a risk")
    func ruleWithAuthorizedRiskIsRisk() {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Secrets",
            authorizedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "*")]
        )

        #expect(allowRisk(for: rule) == .spotlightIndexer)
    }

    @Test("rule without indexer signatures is not a risk")
    func ruleWithoutIndexerIsNotRisk() {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Secrets",
            allowedProcessPaths: ["/usr/bin/mdimport"],
            allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.finder")]
        )

        #expect(allowRisk(for: rule) == .noKnownRisk)
    }

    @Test("WebKit service signature is a risk", arguments: defaultResponsibleProcessChecks.map(\.signingID))
    func webKitSignatureIsRisk(signingID: String) {
        #expect(allowRisk(for: ProcessSignature(teamID: appleTeamID, signingID: signingID)) == .webKitService)
    }

    @Test("third-party team with a WebKit signing ID is not a risk")
    func thirdPartyWebKitSignatureIsNotRisk() {
        #expect(allowRisk(for: ProcessSignature(teamID: "TEAM123", signingID: "com.apple.WebKit.Networking")) == .noKnownRisk)
    }

    @Test("allowlist entries for a WebKit service are a risk", arguments: defaultResponsibleProcessChecks.map(\.signingID))
    func webKitAllowlistEntryIsRisk(signingID: String) {
        #expect(allowRisk(for: AllowlistEntry(signingID: signingID, platformBinary: true)) == .webKitService)
        #expect(allowRisk(for: AncestorAllowlistEntry(signingID: signingID, platformBinary: true)) == .webKitService)
    }

    @Test("signing-ID entry for a WebKit service is a risk, wildcard stays an indexer risk")
    func webKitWildcardEntryIsRisk() {
        #expect(allowRisk(for: AllowlistEntry(signingID: "*", platformBinary: true)) == .spotlightIndexer)
        #expect(allowRisk(for: AllowlistEntry(signingID: "com.apple.WebKit.Networking")) == .webKitService)
    }

    @Test("path-only entry for a WebKit service binary is a risk", arguments: defaultResponsibleProcessChecks.map(\.signingID))
    func webKitPathEntryIsRisk(signingID: String) {
        let path = "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/\(signingID).xpc/Contents/MacOS/\(signingID)"

        #expect(allowRisk(for: AllowlistEntry(processPath: path)) == .webKitService)
        #expect(allowRisk(for: AncestorAllowlistEntry(processPath: path)) == .webKitService)
    }

    @Test("path that only resembles a WebKit service is not a risk")
    func lookalikeWebKitPathIsNotRisk() {
        #expect(allowRisk(for: AllowlistEntry(processPath: "/tmp/com.apple.WebKit.Networking.helper")) == .noKnownRisk)
    }

    @Test("rule allowing a WebKit signature with default checks is not a risk")
    func ruleWithWebKitSignatureAndDefaultChecksIsNotRisk() {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Secrets",
            allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.WebKit.Networking")]
        )

        #expect(allowRisk(for: rule) == .noKnownRisk)
    }

    @Test("rule allowing a WebKit signature with empty checks is a risk", arguments: 0..<3)
    func ruleWithWebKitSignatureAndEmptyChecksIsRisk(listIndex: Int) {
        let webKit = [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.WebKit.GPU")]
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Secrets",
            allowedSignatures: listIndex == 0 ? webKit : [],
            allowedAncestorSignatures: listIndex == 1 ? webKit : [],
            authorizedSignatures: listIndex == 2 ? webKit : [],
            responsibleProcessChecks: []
        )

        #expect(allowRisk(for: rule) == .webKitService)
    }

    @Test("rule risk covers only the WebKit services the checks omit")
    func ruleWithPartialChecksIsRiskForOmittedService() {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Secrets",
            allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.WebKit.WebContent")],
            responsibleProcessChecks: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.WebKit.Networking")]
        )

        #expect(allowRisk(for: rule) == .webKitService)
    }

    @Test("rule allowing a WebKit service path is a risk only when checks omit it")
    func ruleWithWebKitPath() {
        let path = "/System/Library/Frameworks/WebKit.framework/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
        let unchecked = FAARule(protectedPathPrefix: "/Users/*/Secrets", allowedProcessPaths: [path], responsibleProcessChecks: [])
        let uncheckedAncestor = FAARule(protectedPathPrefix: "/Users/*/Secrets", allowedAncestorProcessPaths: [path], responsibleProcessChecks: [])
        let checked = FAARule(protectedPathPrefix: "/Users/*/Secrets", allowedProcessPaths: [path])

        #expect(allowRisk(for: unchecked) == .webKitService)
        #expect(allowRisk(for: uncheckedAncestor) == .webKitService)
        #expect(allowRisk(for: checked) == .noKnownRisk)
    }

    @Test("Spotlight indexer risk wins over WebKit service risk")
    func spotlightWinsOverWebKit() {
        let rule = FAARule(
            protectedPathPrefix: "/Users/*/Secrets",
            allowedSignatures: [
                ProcessSignature(teamID: appleTeamID, signingID: "com.apple.WebKit.GPU"),
                ProcessSignature(teamID: appleTeamID, signingID: "com.apple.mds"),
            ],
            responsibleProcessChecks: []
        )

        #expect(allowRisk(for: rule) == .spotlightIndexer)
    }
}
