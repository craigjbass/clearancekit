//
//  FAARule+AuthorizationEncodingTests.swift
//  clearancekitTests
//

import Foundation
import Testing

@Suite("FAARule authorization fields")
struct FAARuleAuthorizationEncodingTests {
    @Test("round-trips authorizedSignatures, requiresAuthorization and sessionDuration")
    func roundTripsAllAuthorizationFields() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/me/Secrets",
            authorizedSignatures: [ProcessSignature(teamID: "ABCDE12345", signingID: "com.example.app")],
            requiresAuthorization: true,
            authorizationSessionDuration: 600
        )
        let encoded = try JSONEncoder().encode(rule)
        let decoded = try JSONDecoder().decode(FAARule.self, from: encoded)
        #expect(decoded.authorizedSignatures == rule.authorizedSignatures)
        #expect(decoded.requiresAuthorization == true)
        #expect(decoded.authorizationSessionDuration == 600)
    }

    @Test("omits authorization keys from JSON when defaults")
    func omitsDefaultsFromJSON() throws {
        let rule = FAARule(protectedPathPrefix: "/Users/me/Secrets")
        let encoded = try JSONEncoder().encode(rule)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        #expect(!json.contains("authorizedSignatures"))
        #expect(!json.contains("requiresAuthorization"))
        #expect(!json.contains("authorizationSessionDuration"))
    }

    @Test("omits sessionDuration from canonical JSON when equal to 300 default")
    func omitsDefaultSessionDurationFromCanonicalJSON() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/me/Secrets",
            requiresAuthorization: true,
            authorizationSessionDuration: 300
        )
        let encoded = try JSONEncoder().encode(rule)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        #expect(json.contains("requiresAuthorization"))
        #expect(!json.contains("authorizationSessionDuration"))
    }

    @Test("decodes rule written by older build with no authorization keys")
    func decodesLegacyRule() throws {
        let legacy = """
        {"id":"\(UUID().uuidString)","protectedPathPrefix":"/tmp","source":"user","allowedProcessPaths":[],"allowedSignatures":[],"allowedAncestorProcessPaths":[],"allowedAncestorSignatures":[]}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(FAARule.self, from: legacy)
        #expect(decoded.authorizedSignatures.isEmpty)
        #expect(decoded.requiresAuthorization == false)
        #expect(decoded.authorizationSessionDuration == 300)
    }
}
