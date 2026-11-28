//
//  MCPQuietListChangeTests.swift
//  clearancekitTests
//

import Testing
import Foundation

private let indexerHostSigningID = "com.apple.FileDerivativeService.LegacyImporterHost.LegacyImporterHost"

@Suite("MCP quiet list changes")
struct MCPQuietListChangeTests {
    @Test("an Apple signature quiets the signing ID as a platform binary")
    func appleSignatureQuietsPlatformBinary() throws {
        let entry = try quietListEntryForMCPAdd(
            signature: ProcessSignature(teamID: appleTeamID, signingID: indexerHostSigningID),
            processPath: nil,
            existingEntries: []
        )

        #expect(entry.matchCriteria == ProcessMatchCriteria(signingID: indexerHostSigningID, processPath: "", platformBinary: true, teamID: ""))
    }

    @Test("a third-party signature quiets the signing ID for that team only")
    func teamSignatureQuietsTeam() throws {
        let entry = try quietListEntryForMCPAdd(
            signature: ProcessSignature(teamID: "3Z75QZGN66", signingID: "net.sourceforge.grandperspectiv"),
            processPath: nil,
            existingEntries: []
        )

        #expect(entry.matchCriteria == ProcessMatchCriteria(signingID: "net.sourceforge.grandperspectiv", processPath: "", platformBinary: false, teamID: "3Z75QZGN66"))
    }

    @Test("a process path quiets that path only")
    func processPathQuietsPath() throws {
        let entry = try quietListEntryForMCPAdd(signature: nil, processPath: "/usr/local/bin/scanner", existingEntries: [])

        #expect(entry.matchCriteria == ProcessMatchCriteria(signingID: "", processPath: "/usr/local/bin/scanner", platformBinary: false, teamID: ""))
    }

    @Test("a request without a signature or a process path is refused")
    func missingTargetIsRefused() {
        #expect(throws: MCPQuietListChangeError.noTarget) {
            try quietListEntryForMCPAdd(signature: nil, processPath: nil, existingEntries: [])
        }
    }

    @Test("a request with both a signature and a process path is refused")
    func bothTargetsAreRefused() {
        #expect(throws: MCPQuietListChangeError.bothTargets) {
            try quietListEntryForMCPAdd(
                signature: ProcessSignature(teamID: appleTeamID, signingID: indexerHostSigningID),
                processPath: "/usr/local/bin/scanner",
                existingEntries: []
            )
        }
    }

    @Test("a wildcard signature is refused", arguments: [
        ProcessSignature(teamID: appleTeamID, signingID: "*"),
        ProcessSignature(teamID: "*", signingID: "*"),
        ProcessSignature(teamID: "*", signingID: "com.example.app"),
    ])
    func wildcardSignatureIsRefused(signature: ProcessSignature) {
        #expect(throws: MCPQuietListChangeError.wildcardSignature(signature)) {
            try quietListEntryForMCPAdd(signature: signature, processPath: nil, existingEntries: [])
        }
    }

    @Test("a relative process path is refused")
    func relativeProcessPathIsRefused() {
        #expect(throws: MCPQuietListChangeError.relativeProcessPath("bin/scanner")) {
            try quietListEntryForMCPAdd(signature: nil, processPath: "bin/scanner", existingEntries: [])
        }
    }

    @Test("a process that an existing entry already quiets is refused")
    func duplicateIsRefused() {
        let baselineIndexerEntry = baselineQuietList[1]

        #expect(throws: MCPQuietListChangeError.alreadyQuieted(baselineIndexerEntry)) {
            try quietListEntryForMCPAdd(
                signature: ProcessSignature(teamID: appleTeamID, signingID: baselineIndexerEntry.signingID),
                processPath: nil,
                existingEntries: baselineQuietList
            )
        }
    }

    @Test("the duplicate refusal names the existing entry")
    func duplicateRefusalText() {
        let baselineIndexerEntry = baselineQuietList[1]
        let message = MCPQuietListChangeError.alreadyQuieted(baselineIndexerEntry).errorDescription ?? ""

        #expect(message.contains(baselineIndexerEntry.id.uuidString))
    }
}
