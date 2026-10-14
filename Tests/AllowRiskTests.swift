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

    @Test("path-only allowlist entry is not a risk")
    func pathOnlyAllowlistEntryIsNotRisk() {
        let entry = AllowlistEntry(processPath: "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared", platformBinary: true)

        #expect(allowRisk(for: entry) == .noKnownRisk)
    }

    @Test("ancestor allowlist entry for an indexer is a risk")
    func ancestorAllowlistEntryIsRisk() {
        #expect(allowRisk(for: AncestorAllowlistEntry(signingID: "com.apple.mdworker_shared", platformBinary: true)) == .spotlightIndexer)
    }

    @Test("path-only ancestor allowlist entry is not a risk")
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
}
