//
//  CanonicalRulesEncodingTests.swift
//  clearancekitTests
//
//  Pins the byte-level canonical JSON encoding of [FAARule] used by
//  opfilter/Database/Database.swift to compute and verify per-table
//  signatures. The encoder configuration here MUST stay in lock-step
//  with Database.canonicalRulesJSON — these tests catch any drift
//  that would silently invalidate every existing user's signed
//  user_rules row on first launch after upgrade.
//

import Testing
import Foundation

@Suite("Canonical FAARule encoding")
struct CanonicalRulesEncodingTests {

    /// Mirrors Database.canonicalRulesJSON: rules sorted by UUID, JSON
    /// emitted with sorted keys.
    private func canonicalRulesJSON(_ rules: [FAARule]) -> Data {
        let sorted = rules.sorted { $0.id.uuidString < $1.id.uuidString }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try! encoder.encode(sorted)
    }

    // MARK: - Cross-version compatibility

    @Test("v1 (pre-EnforceOnWriteOnly) JSON re-encodes byte-identically")
    func v1JSONReencodesByteIdentical() throws {
        // Hardcoded snapshot of the canonical encoding produced by the
        // build that shipped immediately before issue #130. Forward
        // slashes are escaped as \/ because Database.canonicalRulesJSON
        // uses default JSONEncoder formatting (no .withoutEscapingSlashes).
        // If this string ever needs editing, you are about to invalidate
        // every existing user's signed user_rules — stop and add a
        // migration that re-signs the data instead.
        let v1JSON = #"[{"allowedAncestorProcessPaths":[],"allowedAncestorSignatures":[],"allowedProcessPaths":["\/usr\/bin\/example"],"allowedSignatures":["apple:com.apple.Safari"],"id":"00000000-0000-0000-0000-000000000001","protectedPathPrefix":"\/Users\/*\/Library\/Safari","source":"user"}]"#

        let decoded = try JSONDecoder().decode([FAARule].self, from: Data(v1JSON.utf8))
        let reencoded = canonicalRulesJSON(decoded)

        #expect(String(data: reencoded, encoding: .utf8) == v1JSON)
    }

    @Test("default-false enforceOnWriteOnly is omitted from canonical JSON")
    func defaultFalseEnforceOnWriteOnlyIsOmitted() {
        let rule = FAARule(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            protectedPathPrefix: "/etc/hosts",
            source: .user,
            allowedProcessPaths: ["/bin/cat"]
        )
        let json = String(data: canonicalRulesJSON([rule]), encoding: .utf8) ?? ""

        #expect(!json.contains("enforceOnWriteOnly"))
    }

    // MARK: - Round-trip with the new field

    @Test("enforceOnWriteOnly true survives canonical encode/decode")
    func enforceOnWriteOnlyTrueRoundTrips() throws {
        let original = FAARule(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
            protectedPathPrefix: "/etc/pam.d",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.opendirectoryd")],
            enforceOnWriteOnly: true
        )

        let encoded = canonicalRulesJSON([original])
        let decoded = try JSONDecoder().decode([FAARule].self, from: encoded)

        #expect(decoded.count == 1)
        #expect(decoded[0].enforceOnWriteOnly == true)
        #expect(decoded[0] == original)
    }

    @Test("enforceOnWriteOnly true canonical encoding includes the key")
    func enforceOnWriteOnlyTrueCanonicalIncludesKey() {
        let rule = FAARule(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000003")!,
            protectedPathPrefix: "/etc/ssh",
            source: .user,
            enforceOnWriteOnly: true
        )
        let json = String(data: canonicalRulesJSON([rule]), encoding: .utf8) ?? ""

        #expect(json.contains("\"enforceOnWriteOnly\":true"))
    }

    @Test("default-false requireValidSigning is omitted from canonical JSON")
    func defaultFalseRequireValidSigningIsOmitted() {
        let rule = FAARule(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000004")!,
            protectedPathPrefix: "/etc/hosts",
            source: .user,
            allowedProcessPaths: ["/bin/cat"]
        )
        let json = String(data: canonicalRulesJSON([rule]), encoding: .utf8) ?? ""

        #expect(!json.contains("requireValidSigning"))
    }

    @Test("requireValidSigning true survives canonical encode/decode")
    func requireValidSigningTrueRoundTrips() throws {
        let original = FAARule(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000005")!,
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "*", signingID: "*")],
            requireValidSigning: true
        )

        let encoded = canonicalRulesJSON([original])
        let decoded = try JSONDecoder().decode([FAARule].self, from: encoded)

        #expect(decoded.count == 1)
        #expect(decoded[0].requireValidSigning == true)
        #expect(decoded[0] == original)
    }

    @Test("requireValidSigning true canonical encoding includes the key")
    func requireValidSigningTrueCanonicalIncludesKey() {
        let rule = FAARule(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000006")!,
            protectedPathPrefix: "/protected",
            source: .user,
            requireValidSigning: true
        )
        let json = String(data: canonicalRulesJSON([rule]), encoding: .utf8) ?? ""

        #expect(json.contains("\"requireValidSigning\":true"))
    }

    @Test("default requiresAuthorization is omitted from canonical JSON")
    func defaultRequiresAuthorizationIsOmitted() {
        let rule = FAARule(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000007")!,
            protectedPathPrefix: "/protected",
            source: .user
        )
        let json = String(data: canonicalRulesJSON([rule]), encoding: .utf8) ?? ""

        #expect(!json.contains("requiresAuthorization"))
        #expect(!json.contains("authorizedSignatures"))
        #expect(!json.contains("authorizationSessionDuration"))
    }

    @Test("requiresAuthorization true and non-default duration appear in canonical JSON")
    func requiresAuthorizationTrueAppearsInCanonicalJSON() {
        let rule = FAARule(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000008")!,
            protectedPathPrefix: "/protected",
            source: .user,
            requiresAuthorization: true,
            authorizationSessionDuration: 900
        )
        let json = String(data: canonicalRulesJSON([rule]), encoding: .utf8) ?? ""

        #expect(json.contains("\"requiresAuthorization\":true"))
        #expect(json.contains("\"authorizationSessionDuration\":900"))
    }

    @Test("default authorizationSessionDuration (300) is omitted from canonical JSON")
    func defaultAuthorizationSessionDurationIsOmitted() {
        let rule = FAARule(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000009")!,
            protectedPathPrefix: "/protected",
            source: .user,
            requiresAuthorization: true,
            authorizationSessionDuration: 300
        )
        let json = String(data: canonicalRulesJSON([rule]), encoding: .utf8) ?? ""

        #expect(!json.contains("authorizationSessionDuration"))
    }

    @Test("non-empty authorizedSignatures appear in canonical JSON")
    func authorizedSignaturesAppearInCanonicalJSON() {
        let rule = FAARule(
            id: UUID(uuidString: "00000000-0000-0000-0000-00000000000A")!,
            protectedPathPrefix: "/protected",
            source: .user,
            authorizedSignatures: [ProcessSignature(teamID: "ABCDE12345", signingID: "com.example.app")]
        )
        let json = String(data: canonicalRulesJSON([rule]), encoding: .utf8) ?? ""

        #expect(json.contains("authorizedSignatures"))
        #expect(json.contains("ABCDE12345:com.example.app"))
    }
}
