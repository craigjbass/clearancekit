//
//  PolicyExportDocumentTests.swift
//  clearancekit
//

import Testing
import Foundation

@Suite("PolicyExportDocument")
struct PolicyExportDocumentTests {

    private let sampleRule = FAARule(
        protectedPathPrefix: "/Users/*/Documents",
        source: .user,
        allowedProcessPaths: ["/usr/bin/example"],
        allowedSignatures: [ProcessSignature(teamID: "AAABBBCCC", signingID: "com.example.app")],
        allowedAncestorProcessPaths: [],
        allowedAncestorSignatures: []
    )

    @Test("round-trip encode and decode preserves rules")
    func roundTripPreservesRules() throws {
        let document = PolicyExportDocument(rules: [sampleRule])
        let data = try PolicyExportDocument.encode(document)
        let decoded = try PolicyExportDocument.decode(from: data)

        #expect(decoded.schemaVersion == 1)
        #expect(decoded.rules.count == 1)
        #expect(decoded.rules[0].protectedPathPrefix == sampleRule.protectedPathPrefix)
        #expect(decoded.rules[0].allowedProcessPaths == sampleRule.allowedProcessPaths)
        #expect(decoded.rules[0].allowedSignatures == sampleRule.allowedSignatures)
    }

    @Test("encodes to valid JSON")
    func encodesToValidJSON() throws {
        let document = PolicyExportDocument(rules: [sampleRule])
        let data = try PolicyExportDocument.encode(document)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]

        #expect(json != nil)
        #expect(json?["schemaVersion"] as? Int == 1)
        #expect(json?["exportedAt"] != nil)
        #expect((json?["rules"] as? [[String: Any]])?.count == 1)
    }

    @Test("decode fails for malformed JSON")
    func decodeFailsForMalformedJSON() {
        let badData = Data("not json".utf8)
        #expect(throws: (any Error).self) {
            try PolicyExportDocument.decode(from: badData)
        }
    }

    @Test("encodes and decodes multiple rules")
    func multipleRulesRoundTrip() throws {
        let rules = [
            sampleRule,
            FAARule(
                protectedPathPrefix: "/etc/hosts",
                source: .user,
                allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "*")]
            )
        ]
        let document = PolicyExportDocument(rules: rules)
        let data = try PolicyExportDocument.encode(document)
        let decoded = try PolicyExportDocument.decode(from: data)

        #expect(decoded.rules.count == 2)
        #expect(decoded.rules[0].protectedPathPrefix == "/Users/*/Documents")
        #expect(decoded.rules[1].protectedPathPrefix == "/etc/hosts")
    }

    @Test("empty rules list round-trips correctly")
    func emptyRulesRoundTrip() throws {
        let document = PolicyExportDocument(rules: [])
        let data = try PolicyExportDocument.encode(document)
        let decoded = try PolicyExportDocument.decode(from: data)

        #expect(decoded.rules.isEmpty)
    }
}
