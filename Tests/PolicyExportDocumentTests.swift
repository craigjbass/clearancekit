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

    @Test("enforceOnWriteOnly defaults to false")
    func enforceOnWriteOnlyDefault() {
        let rule = FAARule(protectedPathPrefix: "/tmp")
        #expect(rule.enforceOnWriteOnly == false)
    }

    @Test("enforceOnWriteOnly round-trips when true")
    func enforceOnWriteOnlyRoundTrip() throws {
        let rule = FAARule(
            protectedPathPrefix: "/etc/pam.d",
            allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.opendirectoryd")],
            enforceOnWriteOnly: true
        )
        let document = PolicyExportDocument(rules: [rule])
        let data = try PolicyExportDocument.encode(document)
        let decoded = try PolicyExportDocument.decode(from: data)

        #expect(decoded.rules.count == 1)
        #expect(decoded.rules[0].enforceOnWriteOnly == true)
    }

    @Test("decoding a document without enforceOnWriteOnly defaults to false")
    func decodeWithoutEnforceOnWriteOnly() throws {
        let legacyJSON = """
        {
            "schemaVersion": 1,
            "exportedAt": "2026-01-01T00:00:00Z",
            "rules": [
                {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "protectedPathPrefix": "/legacy",
                    "source": "user",
                    "allowedProcessPaths": [],
                    "allowedSignatures": [],
                    "allowedAncestorProcessPaths": [],
                    "allowedAncestorSignatures": []
                }
            ]
        }
        """
        let data = Data(legacyJSON.utf8)
        let decoded = try PolicyExportDocument.decode(from: data)

        #expect(decoded.rules.count == 1)
        #expect(decoded.rules[0].enforceOnWriteOnly == false)
    }
}
