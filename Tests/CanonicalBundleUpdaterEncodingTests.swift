//
//  CanonicalBundleUpdaterEncodingTests.swift
//  clearancekitTests
//
//  Pins the byte-level canonical JSON encoding of [BundleUpdaterSignature] used
//  by Database.saveBundleUpdaterSignatures to compute the EC-P256 table signature.
//  The encoder config here MUST stay in lock-step with Database.canonicalBundleUpdaterSignaturesJSON.
//

import Testing
import Foundation

@Suite("Canonical BundleUpdaterSignature encoding")
struct CanonicalBundleUpdaterEncodingTests {

    private func canonical(_ signatures: [BundleUpdaterSignature]) -> Data {
        let sorted = signatures.sorted { $0.id.uuidString < $1.id.uuidString }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try! encoder.encode(sorted)
    }

    @Test("empty list encodes to []")
    func emptyListEncodesToBrackets() {
        let json = String(data: canonical([]), encoding: .utf8)
        #expect(json == "[]")
    }

    @Test("single entry encodes with sorted keys")
    func singleEntryEncodesSorted() {
        let sig = BundleUpdaterSignature(
            id: UUID(uuidString: "E5D15228-3561-42CC-972C-54C92B88CB6C")!,
            teamID: "SPARKLE01",
            signingID: "org.sparkle-project.Sparkle"
        )
        let json = String(data: canonical([sig]), encoding: .utf8) ?? ""
        // Keys must be in ASCII sort order: id < signingID < teamID
        let idRange = json.range(of: "\"id\"")!
        let sigRange = json.range(of: "\"signingID\"")!
        let teamRange = json.range(of: "\"teamID\"")!
        #expect(idRange.lowerBound < sigRange.lowerBound)
        #expect(sigRange.lowerBound < teamRange.lowerBound)
    }

    @Test("multiple entries are sorted by id.uuidString")
    func multipleEntriesSortedByID() {
        let sig1 = BundleUpdaterSignature(
            id: UUID(uuidString: "E5D15228-3561-42CC-972C-54C92B88CB6C")!,
            teamID: "TEAM_E",
            signingID: "com.e"
        )
        let sig2 = BundleUpdaterSignature(
            id: UUID(uuidString: "1CE13515-838A-45BD-BD4A-A7468D4F6014")!,
            teamID: "TEAM_1",
            signingID: "com.1"
        )
        // sig2 UUID ("1CE...") sorts before sig1 UUID ("E5D...")
        let json = String(data: canonical([sig1, sig2]), encoding: .utf8) ?? ""
        let range1 = json.range(of: "TEAM_1")!
        let rangeE = json.range(of: "TEAM_E")!
        #expect(range1.lowerBound < rangeE.lowerBound)
    }

    @Test("round-trip encode/decode preserves all fields")
    func roundTripPreservesFields() throws {
        let original = BundleUpdaterSignature(
            id: UUID(uuidString: "E5D15228-3561-42CC-972C-54C92B88CB6C")!,
            teamID: "SPARKLE01",
            signingID: "org.sparkle-project.Sparkle"
        )
        let data = canonical([original])
        let decoded = try JSONDecoder().decode([BundleUpdaterSignature].self, from: data)
        #expect(decoded.count == 1)
        #expect(decoded[0].id == original.id)
        #expect(decoded[0].teamID == original.teamID)
        #expect(decoded[0].signingID == original.signingID)
    }
}
