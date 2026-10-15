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

    @Test("absent ResponsibleProcessChecks gives the default list")
    func responsibleProcessChecksAbsent() {
        let dict: [String: Any] = ["ProtectedPathPrefix": "/a/secret"]

        #expect(parseManagedPolicyRule(dict)?.responsibleProcessChecks == defaultResponsibleProcessChecks)
    }

    @Test("absent ResponsibleProcessChecks gives the WebContent variants")
    func responsibleProcessChecksAbsentGivesWebContentVariants() throws {
        let rule = try #require(parseManagedPolicyRule(["ProtectedPathPrefix": "/a/secret"]))

        #expect(rule.responsibleProcessChecks.contains(ProcessSignature(teamID: appleTeamID, signingID: "com.apple.WebKit.WebContent.CaptivePortal")))
    }

    @Test("ResponsibleProcessChecks entries are parsed")
    func responsibleProcessChecksPresent() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/a/secret",
            "ResponsibleProcessChecks": ["TEAM1:com.example.helper"],
        ]

        #expect(parseManagedPolicyRule(dict)?.responsibleProcessChecks == [ProcessSignature(teamID: "TEAM1", signingID: "com.example.helper")])
    }

    @Test("empty ResponsibleProcessChecks turns the checks off")
    func responsibleProcessChecksEmpty() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/a/secret",
            "ResponsibleProcessChecks": [String](),
        ]

        #expect(parseManagedPolicyRule(dict)?.responsibleProcessChecks == [])
    }

    @Test("DoubleStarParentMatching stop_at_double_star is parsed")
    func doubleStarParentMatchingStopAtDoubleStar() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/a/**/secret",
            "DoubleStarParentMatching": "stop_at_double_star",
        ]

        #expect(parseManagedPolicyRule(dict)?.doubleStarParentMatching == .stopAtDoubleStar)
    }

    @Test("DoubleStarParentMatching all_nested_directories is parsed")
    func doubleStarParentMatchingAllNestedDirectories() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/a/**/secret",
            "DoubleStarParentMatching": "all_nested_directories",
        ]

        #expect(parseManagedPolicyRule(dict)?.doubleStarParentMatching == .allNestedDirectories)
    }

    @Test("absent DoubleStarParentMatching on a double-star pattern gives stopAtDoubleStar")
    func doubleStarParentMatchingAbsentOnDoubleStarPattern() {
        let dict: [String: Any] = ["ProtectedPathPrefix": "/a/**/secret"]

        #expect(parseManagedPolicyRule(dict)?.doubleStarParentMatching == .stopAtDoubleStar)
    }

    @Test("absent DoubleStarParentMatching on a plain pattern gives allNestedDirectories")
    func doubleStarParentMatchingAbsentOnPlainPattern() {
        let dict: [String: Any] = ["ProtectedPathPrefix": "/a/secret"]

        #expect(parseManagedPolicyRule(dict)?.doubleStarParentMatching == .allNestedDirectories)
    }

    @Test("unknown DoubleStarParentMatching value gives allNestedDirectories")
    func doubleStarParentMatchingUnknownValue() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/a/**/secret",
            "DoubleStarParentMatching": "sometimes",
        ]

        #expect(parseManagedPolicyRule(dict)?.doubleStarParentMatching == .allNestedDirectories)
    }

    @Test("DoubleStarParentMatching with non-string type gives allNestedDirectories")
    func doubleStarParentMatchingWrongType() {
        let dict: [String: Any] = [
            "ProtectedPathPrefix": "/a/**/secret",
            "DoubleStarParentMatching": true,
        ]

        #expect(parseManagedPolicyRule(dict)?.doubleStarParentMatching == .allNestedDirectories)
    }
}

// MARK: - parseManagedAllowlistEntry

@Suite("managed allowlist risk")
struct ManagedAllowlistRiskTests {
    @Test("a Networking allowlist entry is reported as a WebKit service risk")
    func networkingEntryIsReported() throws {
        let entry = try #require(parseManagedAllowlistEntry(["SigningID": "com.apple.WebKit.Networking", "PlatformBinary": true]))

        #expect(managedAllowlistEntriesWithRisk([entry]).map(\.id) == [entry.id])
    }

    @Test("an ordinary allowlist entry is not reported")
    func ordinaryEntryIsNotReported() throws {
        let entry = try #require(parseManagedAllowlistEntry(["SigningID": "com.apple.finder", "PlatformBinary": true]))

        #expect(managedAllowlistEntriesWithRisk([entry]).isEmpty)
    }
}

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

// MARK: - parseManagedQuietList

@Suite("parseManagedQuietList")
struct ManagedQuietListParserTests {

    @Test("missing preference is absent")
    func missingPreferenceIsAbsent() {
        guard case .absent = parseManagedQuietList(nil) else {
            Issue.record("Expected .absent")
            return
        }
    }

    @Test("parses valid entries")
    func parsesValidEntries() {
        let id = UUID()
        let preference: [Any] = [
            ["ID": id.uuidString, "SigningID": "com.example.noisy", "TeamID": "TEAM123"],
            ["ProcessPath": "/usr/local/bin/noisy"],
            ["SigningID": "com.apple.noisy", "PlatformBinary": true] as [String: Any],
        ]

        guard case .entries(let entries) = parseManagedQuietList(preference) else {
            Issue.record("Expected .entries")
            return
        }

        #expect(entries.count == 3)
        #expect(entries[0] == QuietListEntry(id: id, signingID: "com.example.noisy", processPath: "", platformBinary: false, teamID: "TEAM123"))
        #expect(entries[1].processPath == "/usr/local/bin/noisy")
        #expect(entries[2].platformBinary)
    }

    @Test("skips an entry with no SigningID or ProcessPath")
    func skipsInvalidEntry() {
        let preference: [Any] = [
            ["TeamID": "TEAM123"],
            ["SigningID": "com.example.noisy"],
        ]

        guard case .entries(let entries) = parseManagedQuietList(preference) else {
            Issue.record("Expected .entries")
            return
        }

        #expect(entries.map(\.signingID) == ["com.example.noisy"])
    }

    @Test("skips an item that is not a dictionary")
    func skipsNonDictionaryItem() {
        let preference: [Any] = [
            "com.example.noisy",
            ["SigningID": "com.example.other"],
        ]

        guard case .entries(let entries) = parseManagedQuietList(preference) else {
            Issue.record("Expected .entries")
            return
        }

        #expect(entries.map(\.signingID) == ["com.example.other"])
    }

    @Test("a value that is not an array is malformed")
    func nonArrayIsMalformed() {
        guard case .malformed = parseManagedQuietList("com.example.noisy") else {
            Issue.record("Expected .malformed")
            return
        }
    }

    @Test("derives a deterministic ID from SigningID when ID is absent")
    func derivesDeterministicID() {
        let entry = parseManagedQuietListEntry(["SigningID": "com.example.noisy"])

        #expect(entry?.id == uuidV5(namespace: uuidV5URLNamespace, name: "com.example.noisy"))
    }
}

@Suite("ManagedQuietListPreference.resolved")
struct ManagedQuietListPreferenceTests {
    private let previous = [QuietListEntry(id: UUID(), signingID: "com.example.previous", processPath: "", platformBinary: false, teamID: "")]

    @Test("absent resolves to an empty list")
    func absentResolvesToEmpty() {
        #expect(ManagedQuietListPreference.absent.resolved(keeping: previous).isEmpty)
    }

    @Test("entries resolve to the new entries")
    func entriesResolveToNewEntries() {
        let replacement = [QuietListEntry(id: UUID(), signingID: "com.example.new", processPath: "", platformBinary: false, teamID: "")]

        #expect(ManagedQuietListPreference.entries(replacement).resolved(keeping: previous) == replacement)
    }

    @Test("malformed keeps the previous list")
    func malformedKeepsPrevious() {
        #expect(ManagedQuietListPreference.malformed.resolved(keeping: previous) == previous)
    }
}
