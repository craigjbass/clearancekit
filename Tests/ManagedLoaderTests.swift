//
//  ManagedLoaderTests.swift
//  clearancekitTests
//

import Testing
import Foundation

// MARK: - parseManagedPolicyRule

@Suite("parseManagedPolicyRule")
struct ManagedPolicyRuleParserTests {

    @Test("returns a rule with all fields populated")
    func allFieldsPopulated() {
        let id = UUID()
        let dict: [String: Any] = [
            "ID": id.uuidString,
            "ProtectedPathPrefix": "/protected/path",
            "AllowedProcessPaths": ["/usr/bin/tool"],
            "AllowedSignatures": ["TEAM1:com.example.app"],
            "AllowedAncestorProcessPaths": ["/usr/bin/parent"],
            "AllowedAncestorSignatures": ["TEAM2:com.example.parent"],
        ]

        let rule = parseManagedPolicyRule(dict)

        #expect(rule?.id == id)
        #expect(rule?.protectedPathPrefix == "/protected/path")
        #expect(rule?.source == .mdm)
        #expect(rule?.allowedProcessPaths == ["/usr/bin/tool"])
        #expect(rule?.allowedSignatures == [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")])
        #expect(rule?.allowedAncestorProcessPaths == ["/usr/bin/parent"])
        #expect(rule?.allowedAncestorSignatures == [ProcessSignature(teamID: "TEAM2", signingID: "com.example.parent")])
    }

    @Test("returns nil when ProtectedPathPrefix is missing")
    func missingProtectedPathPrefix() {
        let dict: [String: Any] = ["AllowedProcessPaths": ["/usr/bin/tool"]]

        #expect(parseManagedPolicyRule(dict) == nil)
    }

    @Test("returns nil when ProtectedPathPrefix is empty")
    func emptyProtectedPathPrefix() {
        let dict: [String: Any] = ["ProtectedPathPrefix": ""]

        #expect(parseManagedPolicyRule(dict) == nil)
    }

    @Test("uses explicit ID when a valid UUID string is present")
    func explicitIDIsUsed() {
        let id = UUID()
        let dict: [String: Any] = [
            "ID": id.uuidString,
            "ProtectedPathPrefix": "/any/path",
        ]

        #expect(parseManagedPolicyRule(dict)?.id == id)
    }

    @Test("derives deterministic ID from ProtectedPathPrefix when ID is absent")
    func deterministicIDFromPath() {
        let path = "/protected/deterministic"
        let dict: [String: Any] = ["ProtectedPathPrefix": path]

        let expected = uuidV5(namespace: uuidV5URLNamespace, name: path)
        #expect(parseManagedPolicyRule(dict)?.id == expected)
    }

    @Test("derives deterministic ID from ProtectedPathPrefix when ID is not a valid UUID")
    func deterministicIDWhenIDIsInvalid() {
        let path = "/protected/invalid-id"
        let dict: [String: Any] = [
            "ID": "not-a-uuid",
            "ProtectedPathPrefix": path,
        ]

        let expected = uuidV5(namespace: uuidV5URLNamespace, name: path)
        #expect(parseManagedPolicyRule(dict)?.id == expected)
    }

    @Test("parses AllowedSignatures in teamID:signingID format")
    func signaturesAreParsed() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/some/path",
            "AllowedSignatures": ["apple:com.apple.Safari", "37KMK6XFTT:*"],
        ]

        let rule = parseManagedPolicyRule(dict)
        #expect(rule?.allowedSignatures == [
            ProcessSignature(teamID: "apple",       signingID: "com.apple.Safari"),
            ProcessSignature(teamID: "37KMK6XFTT",  signingID: "*"),
        ])
    }

    @Test("drops signature strings that are missing the colon separator")
    func signatureWithoutColonIsDropped() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/some/path",
            "AllowedSignatures": ["no-colon-here"],
        ]

        #expect(parseManagedPolicyRule(dict)?.allowedSignatures.isEmpty == true)
    }

    @Test("empty AllowedProcessPaths produces rule with no allowed process paths")
    func emptyAllowedProcessPaths() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/some/path",
            "AllowedProcessPaths": [String](),
        ]

        #expect(parseManagedPolicyRule(dict)?.allowedProcessPaths.isEmpty == true)
    }

    @Test("empty AllowedSignatures produces rule with no allowed signatures")
    func emptyAllowedSignatures() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/some/path",
            "AllowedSignatures": [String](),
        ]

        #expect(parseManagedPolicyRule(dict)?.allowedSignatures.isEmpty == true)
    }

    @Test("absent optional arrays default to empty")
    func absentOptionalArraysDefaultToEmpty() {
        let dict: [String: Any] = ["ProtectedPathPrefix": "/minimal/path"]

        let rule = parseManagedPolicyRule(dict)
        #expect(rule?.allowedProcessPaths.isEmpty == true)
        #expect(rule?.allowedSignatures.isEmpty == true)
        #expect(rule?.allowedAncestorProcessPaths.isEmpty == true)
        #expect(rule?.allowedAncestorSignatures.isEmpty == true)
    }

    @Test("EnforceOnWriteOnly true is parsed")
    func enforceOnWriteOnlyTrue() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/etc/pam.d",
            "EnforceOnWriteOnly": true,
        ]

        #expect(parseManagedPolicyRule(dict)?.enforceOnWriteOnly == true)
    }

    @Test("EnforceOnWriteOnly false is parsed")
    func enforceOnWriteOnlyFalse() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/etc/pam.d",
            "EnforceOnWriteOnly": false,
        ]

        #expect(parseManagedPolicyRule(dict)?.enforceOnWriteOnly == false)
    }

    @Test("absent EnforceOnWriteOnly defaults to false")
    func enforceOnWriteOnlyAbsent() {
        let dict: [String: Any] = ["ProtectedPathPrefix": "/etc/pam.d"]

        #expect(parseManagedPolicyRule(dict)?.enforceOnWriteOnly == false)
    }

    @Test("EnforceOnWriteOnly with non-bool type defaults to false")
    func enforceOnWriteOnlyWrongType() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/etc/pam.d",
            "EnforceOnWriteOnly": "true",  // String, not Bool
        ]

        #expect(parseManagedPolicyRule(dict)?.enforceOnWriteOnly == false)
    }
}

// MARK: - parseManagedAllowlistEntry

@Suite("parseManagedAllowlistEntry")
struct ManagedAllowlistEntryParserTests {

    @Test("returns an entry matching by SigningID")
    func entryWithSigningID() {
        let dict: [String: Any] = ["SigningID": "com.example.tool"]

        let entry = parseManagedAllowlistEntry(dict)
        #expect(entry?.signingID == "com.example.tool")
        #expect(entry?.processPath == "")
    }

    @Test("returns an entry matching by ProcessPath")
    func entryWithProcessPath() {
        let dict: [String: Any] = ["ProcessPath": "/usr/bin/tool"]

        let entry = parseManagedAllowlistEntry(dict)
        #expect(entry?.processPath == "/usr/bin/tool")
        #expect(entry?.signingID == "")
    }

    @Test("returns nil when both SigningID and ProcessPath are absent")
    func bothAbsentReturnsNil() {
        let dict: [String: Any] = ["PlatformBinary": true]

        #expect(parseManagedAllowlistEntry(dict) == nil)
    }

    @Test("returns nil when both SigningID and ProcessPath are empty strings")
    func bothEmptyReturnsNil() {
        let dict: [String: Any] = ["SigningID": "", "ProcessPath": ""]

        #expect(parseManagedAllowlistEntry(dict) == nil)
    }

    @Test("reads PlatformBinary true correctly")
    func platformBinaryTrue() {
        let dict: [String: Any] = ["SigningID": "com.apple.tool", "PlatformBinary": true]

        #expect(parseManagedAllowlistEntry(dict)?.platformBinary == true)
    }

    @Test("defaults PlatformBinary to false when absent")
    func platformBinaryDefaultsFalse() {
        let dict: [String: Any] = ["SigningID": "com.example.app"]

        #expect(parseManagedAllowlistEntry(dict)?.platformBinary == false)
    }

    @Test("applies TeamID constraint")
    func teamIDIsApplied() {
        let dict: [String: Any] = ["SigningID": "com.example.app", "TeamID": "ABCDE12345"]

        #expect(parseManagedAllowlistEntry(dict)?.teamID == "ABCDE12345")
    }

    @Test("uses explicit ID when a valid UUID string is present")
    func explicitIDIsUsed() {
        let id = UUID()
        let dict: [String: Any] = ["ID": id.uuidString, "SigningID": "com.example.app"]

        #expect(parseManagedAllowlistEntry(dict)?.id == id)
    }

    @Test("derives deterministic ID from SigningID when ID is absent")
    func deterministicIDFromSigningID() {
        let signingID = "com.example.deterministic"
        let dict: [String: Any] = ["SigningID": signingID]

        let expected = uuidV5(namespace: uuidV5URLNamespace, name: signingID)
        #expect(parseManagedAllowlistEntry(dict)?.id == expected)
    }

    @Test("derives deterministic ID from ProcessPath when SigningID is absent")
    func deterministicIDFromProcessPath() {
        let processPath = "/usr/bin/deterministic"
        let dict: [String: Any] = ["ProcessPath": processPath]

        let expected = uuidV5(namespace: uuidV5URLNamespace, name: processPath)
        #expect(parseManagedAllowlistEntry(dict)?.id == expected)
    }

    @Test("deterministic UUID uses same namespace and algorithm as ManagedPolicyLoader derivation")
    func deterministicIDMatchesPolicyLoaderDerivation() {
        let sharedName = "/shared/path"
        let allowlistEntry = parseManagedAllowlistEntry(["ProcessPath": sharedName])
        let policyRule     = parseManagedPolicyRule(["ProtectedPathPrefix": sharedName])

        #expect(allowlistEntry?.id == policyRule?.id)
    }
}
