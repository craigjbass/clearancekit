//
//  PolicyDecisionTests.swift
//  clearancekit
//

import Testing
import Foundation
import os

// MARK: - Path matching

@Suite("pathIsProtected")
struct PathMatchingTests {
    @Test("simple prefix match")
    func simplePrefixMatch() {
        #expect(pathIsProtected("/Library/App/clearancekit/store.db", by: "/Library/App/clearancekit"))
    }

    @Test("exact path matches")
    func exactPathMatch() {
        #expect(pathIsProtected("/Library/App/clearancekit", by: "/Library/App/clearancekit"))
    }

    @Test("path with trailing slash in pattern")
    func trailingSlashInPattern() {
        #expect(pathIsProtected("/Library/App/clearancekit/file.txt", by: "/Library/App/clearancekit/"))
    }

    @Test("rejects path that shares a prefix but not a component boundary")
    func rejectsPartialComponentMatch() {
        #expect(!pathIsProtected("/Library/App/clearancekit-extra/file", by: "/Library/App/clearancekit"))
    }

    @Test("rejects unrelated path")
    func rejectsUnrelatedPath() {
        #expect(!pathIsProtected("/Users/someone/Documents", by: "/Library/App/clearancekit"))
    }

    @Test("single-star matches within one component")
    func singleStarMatchesComponent() {
        #expect(pathIsProtected("/Users/admin/Documents/secret.txt", by: "/Users/*/Documents"))
    }

    @Test("single-star does not cross component boundary")
    func singleStarDoesNotCrossBoundary() {
        #expect(!pathIsProtected("/Users/admin/deep/Documents/secret.txt", by: "/Users/*/Documents"))
    }

    @Test("double-star matches multiple levels")
    func doubleStarMatchesMultipleLevels() {
        #expect(pathIsProtected("/a/b/c/d/e/file.txt", by: "/a/**/file.txt"))
    }

    @Test("double-star matches zero levels")
    func doubleStarMatchesZeroLevels() {
        #expect(pathIsProtected("/a/file.txt", by: "/a/**/file.txt"))
    }

    @Test("double-star at end matches everything beneath")
    func doubleStarAtEnd() {
        #expect(pathIsProtected("/protected/deep/nested/file", by: "/protected/**"))
    }

    @Test("question mark matches single character")
    func questionMarkMatchesSingleChar() {
        #expect(pathIsProtected("/data/v1/file", by: "/data/v?/file"))
    }

    @Test("question mark does not match zero characters")
    func questionMarkRequiresCharacter() {
        #expect(!pathIsProtected("/data/v/file", by: "/data/v?/file"))
    }

    @Test("combined wildcards")
    func combinedWildcards() {
        #expect(pathIsProtected("/Users/admin/Library/file.txt", by: "/Users/?dmin/Lib*"))
    }

    @Test("pattern with no wildcards is a prefix check — deeper paths match")
    func prefixCheckAllowsDeeperPaths() {
        #expect(pathIsProtected("/foo/bar/baz/deep/file", by: "/foo/bar"))
    }
}

@Suite("pathContainsProtectedPaths")
struct PathContainsProtectedPathsTests {
    @Test("directory matched by the single-star pattern's parent contains protected paths")
    func directoryAboveSingleStarContainsProtectedPaths() {
        #expect(pathContainsProtectedPaths("/Users/develop/goal", by: "/Users/develop/goal/*", matching: .allNestedDirectories))
    }

    @Test("grandparent contains protected paths")
    func grandparentContainsProtectedPaths() {
        #expect(pathContainsProtectedPaths("/Users/develop", by: "/Users/develop/goal/*", matching: .allNestedDirectories))
    }

    @Test("root contains every protected path")
    func rootContainsProtectedPaths() {
        #expect(pathContainsProtectedPaths("/", by: "/Library/Application Support/clearancekit", matching: .allNestedDirectories))
    }

    @Test("parent of a literal prefix contains protected paths")
    func parentOfLiteralPrefix() {
        #expect(pathContainsProtectedPaths("/Library/Application Support", by: "/Library/Application Support/clearancekit", matching: .allNestedDirectories))
    }

    @Test("parent matched through a wildcard component contains protected paths")
    func parentThroughWildcardComponent() {
        #expect(pathContainsProtectedPaths("/Users/admin/Library", by: "/Users/*/Library/Mail", matching: .allNestedDirectories))
    }

    @Test("double-star pattern makes every deeper directory a parent")
    func doubleStarMakesDeeperDirectoriesParents() {
        #expect(pathContainsProtectedPaths("/a/b/c", by: "/a/**/secret", matching: .allNestedDirectories))
    }

    @Test("trailing slash in the pattern is ignored")
    func trailingSlashInPattern() {
        #expect(pathContainsProtectedPaths("/Users/develop", by: "/Users/develop/goal/", matching: .allNestedDirectories))
    }

    @Test("the protected path itself is not reported")
    func protectedPathItselfIsNotReported() {
        #expect(!pathContainsProtectedPaths("/Users/develop/goal", by: "/Users/develop/goal", matching: .allNestedDirectories))
    }

    @Test("a path below the pattern is not reported")
    func pathBelowPatternIsNotReported() {
        #expect(!pathContainsProtectedPaths("/Users/develop/goal/gold", by: "/Users/develop/goal/*", matching: .allNestedDirectories))
    }

    @Test("a sibling that shares a string prefix is not reported")
    func siblingWithSharedStringPrefix() {
        #expect(!pathContainsProtectedPaths("/Users/developer", by: "/Users/develop/goal/*", matching: .allNestedDirectories))
    }

    @Test("an unrelated directory is not reported")
    func unrelatedDirectory() {
        #expect(!pathContainsProtectedPaths("/Users/admin/Documents", by: "/Users/*/Library/Mail", matching: .allNestedDirectories))
    }
}

@Suite("pathContainsProtectedPaths with stopAtDoubleStar")
struct PathContainsProtectedPathsStopAtDoubleStarTests {
    private let inMemoryPattern = "/private/var/folders/**/NSCreateObjectFileImageFromMemory-*"

    @Test("directory above the double-star contains protected paths")
    func directoryAboveDoubleStar() {
        #expect(pathContainsProtectedPaths("/private/var", by: inMemoryPattern, matching: .stopAtDoubleStar))
    }

    @Test("directory at the double-star position contains protected paths")
    func directoryAtDoubleStarPosition() {
        #expect(pathContainsProtectedPaths("/private/var/folders", by: inMemoryPattern, matching: .stopAtDoubleStar))
    }

    @Test("directory below the double-star does not count")
    func directoryBelowDoubleStar() {
        #expect(!pathContainsProtectedPaths("/private/var/folders/zz/abc/T", by: inMemoryPattern, matching: .stopAtDoubleStar))
    }

    @Test("directory below the double-star counts with allNestedDirectories")
    func directoryBelowDoubleStarWithAllNestedDirectories() {
        #expect(pathContainsProtectedPaths("/private/var/folders/zz/abc/T", by: inMemoryPattern, matching: .allNestedDirectories))
    }

    @Test("double-star directly below root makes only root a parent")
    func doubleStarDirectlyBelowRoot() {
        #expect(pathContainsProtectedPaths("/", by: "/**/secret", matching: .stopAtDoubleStar))
        #expect(!pathContainsProtectedPaths("/Users", by: "/**/secret", matching: .stopAtDoubleStar))
    }

    @Test("pattern without a double-star component is not changed")
    func patternWithoutDoubleStarIsNotChanged() {
        #expect(pathContainsProtectedPaths("/Users/develop", by: "/Users/develop/goal/*", matching: .stopAtDoubleStar))
    }
}

@Suite("DoubleStarParentMatching")
struct DoubleStarParentMatchingTests {
    @Test("pattern with a double-star component implies stopAtDoubleStar")
    func doubleStarPatternImpliesStopAtDoubleStar() {
        #expect(DoubleStarParentMatching.implied(by: "/a/**/secret") == .stopAtDoubleStar)
    }

    @Test("pattern without a double-star component implies allNestedDirectories")
    func plainPatternImpliesAllNestedDirectories() {
        #expect(DoubleStarParentMatching.implied(by: "/Users/*/Library/Mail") == .allNestedDirectories)
    }

    @Test("double-star inside a component is not a double-star component")
    func doubleStarInsideComponentIsNotDoubleStarComponent() {
        #expect(!patternContainsDoubleStarComponent("/a/b**/c"))
        #expect(patternContainsDoubleStarComponent("/a/**/c"))
    }

    @Test("external names parse to the matching case")
    func externalNamesParse() {
        #expect(DoubleStarParentMatching(rawValue: "all_nested_directories") == .allNestedDirectories)
        #expect(DoubleStarParentMatching(rawValue: "stop_at_double_star") == .stopAtDoubleStar)
        #expect(DoubleStarParentMatching(rawValue: "stopAtDoubleStar") == nil)
    }

    @Test("FAARule.init uses allNestedDirectories")
    func initUsesAllNestedDirectories() {
        #expect(FAARule(protectedPathPrefix: "/a/**/secret").doubleStarParentMatching == .allNestedDirectories)
    }

    @Test("compatibility mode applies only to double-star patterns set to stopAtDoubleStar")
    func compatibilityModeAppliesOnlyToDoubleStarPatterns() {
        #expect(FAARule(protectedPathPrefix: "/a/**/secret", doubleStarParentMatching: .stopAtDoubleStar).usesDoubleStarCompatibilityMode)
        #expect(!FAARule(protectedPathPrefix: "/a/secret", doubleStarParentMatching: .stopAtDoubleStar).usesDoubleStarCompatibilityMode)
        #expect(!FAARule(protectedPathPrefix: "/a/**/secret").usesDoubleStarCompatibilityMode)
    }
}

// MARK: - ProcessSignature

@Suite("ProcessSignature")
struct ProcessSignatureTests {
    @Test("exact match")
    func exactMatch() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")
        #expect(sig.matches(resolvedTeamID: "TEAM1", signingID: "com.example.app"))
    }

    @Test("wildcard signingID matches any")
    func wildcardSigningID() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "*")
        #expect(sig.matches(resolvedTeamID: "TEAM1", signingID: "com.anything"))
    }

    @Test("team mismatch rejects")
    func teamMismatch() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "*")
        #expect(!sig.matches(resolvedTeamID: "TEAM2", signingID: "com.anything"))
    }

    @Test("signing ID mismatch rejects")
    func signingIDMismatch() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")
        #expect(!sig.matches(resolvedTeamID: "TEAM1", signingID: "com.example.other"))
    }

    @Test("universal wildcard *:* matches any team and signing ID")
    func universalWildcardMatchesAny() {
        let sig = ProcessSignature(teamID: "*", signingID: "*")
        #expect(sig.matches(resolvedTeamID: "apple", signingID: "com.apple.Safari"))
        #expect(sig.matches(resolvedTeamID: "TEAM1", signingID: "com.example.app"))
        #expect(sig.matches(resolvedTeamID: "EQHXZ8M8AV", signingID: "com.google.Chrome"))
    }

    @Test("wildcard team with specific signing ID matches only that signing ID")
    func wildcardTeamSpecificSigningID() {
        let sig = ProcessSignature(teamID: "*", signingID: "com.apple.Safari")
        #expect(sig.matches(resolvedTeamID: "apple", signingID: "com.apple.Safari"))
        #expect(sig.matches(resolvedTeamID: "OTHERTEAM", signingID: "com.apple.Safari"))
        #expect(!sig.matches(resolvedTeamID: "apple", signingID: "com.apple.Mail"))
    }

    @Test("round-trips through JSON")
    func jsonRoundTrip() throws {
        let sig = ProcessSignature(teamID: "ABC", signingID: "com.test")
        let data = try JSONEncoder().encode(sig)
        let decoded = try JSONDecoder().decode(ProcessSignature.self, from: data)
        #expect(decoded == sig)
    }
}

// MARK: - AllowlistEntry

@Suite("AllowlistEntry.matches")
struct AllowlistEntryTests {

    // MARK: Signing-ID-based entries

    @Test("signing ID match")
    func signingIDMatch() {
        let entry = AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)
        #expect(entry.matches(processPath: "/anything", signingID: "com.apple.finder", teamID: "apple"))
    }

    @Test("signing ID mismatch")
    func signingIDMismatch() {
        let entry = AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)
        #expect(!entry.matches(processPath: "/anything", signingID: "com.apple.safari", teamID: "apple"))
    }

    @Test("platform binary requires apple team ID")
    func platformBinaryRequiresAppleTeamID() {
        let entry = AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)
        #expect(!entry.matches(processPath: "/anything", signingID: "com.apple.finder", teamID: "SOMETEAM"))
        #expect(!entry.matches(processPath: "/anything", signingID: "com.apple.finder", teamID: ""))
        #expect(entry.matches(processPath: "/anything", signingID: "com.apple.finder", teamID: "apple"))
    }

    @Test("third-party signing ID with matching team")
    func thirdPartySigningWithTeam() {
        let entry = AllowlistEntry(signingID: "com.acme.tool", teamID: "ACME99")
        #expect(entry.matches(processPath: "/Applications/Acme.app/Contents/MacOS/Acme", signingID: "com.acme.tool", teamID: "ACME99"))
    }

    @Test("third-party signing ID with wrong team rejected")
    func thirdPartySigningWrongTeam() {
        let entry = AllowlistEntry(signingID: "com.acme.tool", teamID: "ACME99")
        #expect(!entry.matches(processPath: "/anything", signingID: "com.acme.tool", teamID: "EVIL77"))
    }

    @Test("signing ID entry without team constraint accepts any team")
    func signingIDNoTeamConstraint() {
        let entry = AllowlistEntry(signingID: "com.example.app")
        #expect(entry.matches(processPath: "", signingID: "com.example.app", teamID: "ANYTEAM"))
        #expect(entry.matches(processPath: "", signingID: "com.example.app", teamID: ""))
    }

    @Test("signing ID takes priority over process path in same entry")
    func signingIDPriorityOverPath() {
        let entry = AllowlistEntry(signingID: "com.example.app", processPath: "/usr/bin/example")
        #expect(entry.matches(processPath: "/wrong/path", signingID: "com.example.app", teamID: ""))
    }

    // MARK: Path-based entries

    @Test("path-based match")
    func pathBasedMatch() {
        let entry = AllowlistEntry(processPath: "/usr/bin/something")
        #expect(entry.matches(processPath: "/usr/bin/something", signingID: "", teamID: ""))
    }

    @Test("path-based mismatch")
    func pathBasedMismatch() {
        let entry = AllowlistEntry(processPath: "/usr/bin/something")
        #expect(!entry.matches(processPath: "/usr/bin/other", signingID: "", teamID: ""))
    }

    @Test("path-based match is exact — no prefix matching")
    func pathBasedExactOnly() {
        let entry = AllowlistEntry(processPath: "/usr/bin/tool")
        #expect(!entry.matches(processPath: "/usr/bin/tool-extra", signingID: "", teamID: ""))
        #expect(!entry.matches(processPath: "/usr/bin/tool/child", signingID: "", teamID: ""))
    }

    @Test("path-based entry ignores signing identity")
    func pathBasedIgnoresSigningID() {
        let entry = AllowlistEntry(processPath: "/usr/bin/tool")
        #expect(entry.matches(processPath: "/usr/bin/tool", signingID: "com.evil.malware", teamID: "EVIL"))
    }

    @Test("path-based entry with platform binary flag requires apple team ID")
    func pathBasedPlatformBinary() {
        let entry = AllowlistEntry(processPath: "/Library/Apple/XProtect", platformBinary: true)
        #expect(entry.matches(processPath: "/Library/Apple/XProtect", signingID: "", teamID: "apple"))
        #expect(!entry.matches(processPath: "/Library/Apple/XProtect", signingID: "", teamID: ""))
        #expect(!entry.matches(processPath: "/Library/Apple/XProtect", signingID: "", teamID: "TEAM"))
    }

    // MARK: Edge cases

    @Test("team ID constraint enforced for non-platform-binary")
    func teamIDConstraint() {
        let entry = AllowlistEntry(signingID: "com.example.app", teamID: "TEAM1")
        #expect(entry.matches(processPath: "", signingID: "com.example.app", teamID: "TEAM1"))
        #expect(!entry.matches(processPath: "", signingID: "com.example.app", teamID: "TEAM2"))
    }

    @Test("entry with neither signingID nor processPath matches nothing")
    func emptyEntryMatchesNothing() {
        let entry = AllowlistEntry()
        #expect(!entry.matches(processPath: "/anything", signingID: "anything", teamID: "anything"))
    }

    // MARK: Wildcard signing ID

    @Test("wildcard signing ID matches any signing ID with matching team")
    func wildcardSigningIDMatchesAnyWithTeam() {
        let entry = AllowlistEntry(signingID: "*", teamID: "ACME99")
        #expect(entry.matches(processPath: "/anything", signingID: "com.acme.tool", teamID: "ACME99"))
        #expect(entry.matches(processPath: "/anything", signingID: "com.acme.other", teamID: "ACME99"))
    }

    @Test("wildcard signing ID rejects wrong team")
    func wildcardSigningIDRejectsWrongTeam() {
        let entry = AllowlistEntry(signingID: "*", teamID: "ACME99")
        #expect(!entry.matches(processPath: "/anything", signingID: "com.acme.tool", teamID: "EVIL77"))
    }

    @Test("wildcard signing ID with platform binary matches any apple process")
    func wildcardSigningIDPlatformBinary() {
        let entry = AllowlistEntry(signingID: "*", platformBinary: true)
        #expect(entry.matches(processPath: "/anything", signingID: "com.apple.anything", teamID: "apple"))
        #expect(!entry.matches(processPath: "/anything", signingID: "com.acme.tool", teamID: "ACME99"))
    }
}

// MARK: - evaluateAccess

@Suite("evaluateAccess")
struct AccessEvaluationTests {
    let ruleID = UUID()

    private func ruleProtecting(
        _ path: String,
        allowedProcessPaths: [String] = [],
        allowedSignatures: [ProcessSignature] = [],
        allowedAncestorProcessPaths: [String] = [],
        allowedAncestorSignatures: [ProcessSignature] = []
    ) -> FAARule {
        FAARule(
            id: ruleID,
            protectedPathPrefix: path,
            allowedProcessPaths: allowedProcessPaths,
            allowedSignatures: allowedSignatures,
            allowedAncestorProcessPaths: allowedAncestorProcessPaths,
            allowedAncestorSignatures: allowedAncestorSignatures
        )
    }

    private func decide(
        rules: [FAARule] = [],
        allowlist: [AllowlistEntry] = [],
        path: String = "/unrelated",
        processPath: String = "/bin/test",
        teamID: String = "",
        signingID: String = "",
        accessKind: AccessKind = .write,
        ancestors: [AncestorInfo] = []
    ) async -> PolicyDecision {
        await evaluateAccess(
            rules: rules,
            allowlist: allowlist,
            path: path,
            process: ProcessFacts(processPath: processPath, teamID: teamID, signingID: signingID),
            responsibleProcess: .unknown,
            accessKind: accessKind,
            ancestryProvider: { ancestors },
            responsibleAncestryProvider: { [] }
        )
    }

    // MARK: Global allowlist — signing-based

    @Test("platform binary on allowlist is globally allowed")
    func platformBinaryGloballyAllowed() async {
        let allowlist = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        let rules = [ruleProtecting("/protected")]
        let decision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/System/Finder", teamID: "apple", signingID: "com.apple.finder")
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("platform binary with non-empty team ID is not globally allowed")
    func platformBinaryWrongTeamNotAllowed() async {
        let allowlist = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        let rules = [ruleProtecting("/protected")]
        let decision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/anything", teamID: "SOMETEAM", signingID: "com.apple.finder")
        #expect(!decision.isAllowed)
    }

    @Test("third-party app on allowlist by team + signing ID is globally allowed")
    func thirdPartyGloballyAllowed() async {
        let allowlist = [AllowlistEntry(signingID: "com.acme.backup", teamID: "ACME99")]
        let rules = [ruleProtecting("/protected")]
        let decision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/Applications/AcmeBackup", teamID: "ACME99", signingID: "com.acme.backup")
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("third-party app with wrong team ID falls through to policy")
    func thirdPartyWrongTeamHitsPolicy() async {
        let allowlist = [AllowlistEntry(signingID: "com.acme.backup", teamID: "ACME99")]
        let rules = [ruleProtecting("/protected")]
        let decision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/anything", teamID: "EVIL77", signingID: "com.acme.backup")
        #expect(!decision.isAllowed)
        #expect(decision.matchedRuleID == ruleID)
    }

    // MARK: Global allowlist — path-based

    @Test("process on allowlist by path is globally allowed")
    func pathBasedGloballyAllowed() async {
        let allowlist = [AllowlistEntry(processPath: "/usr/libexec/xprotect")]
        let rules = [ruleProtecting("/protected")]
        let decision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/usr/libexec/xprotect")
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("path-based allowlist entry rejects different path — falls through to policy")
    func pathMismatchHitsPolicy() async {
        let allowlist = [AllowlistEntry(processPath: "/usr/libexec/xprotect")]
        let rules = [ruleProtecting("/protected")]
        let decision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/usr/bin/evil")
        #expect(!decision.isAllowed)
    }

    @Test("path-based allowlist does not prefix match")
    func pathAllowlistNoPrefixMatch() async {
        let allowlist = [AllowlistEntry(processPath: "/usr/bin/tool")]
        let rules = [ruleProtecting("/protected")]
        let decision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/usr/bin/tool-extended")
        #expect(!decision.isAllowed)
    }

    @Test("path-based platform binary allowlist entry requires apple team ID")
    func pathPlatformBinaryEnforcesTeam() async {
        let allowlist = [AllowlistEntry(processPath: "/Library/Apple/XProtect", platformBinary: true)]
        let rules = [ruleProtecting("/protected")]

        let allowed = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/Library/Apple/XProtect", teamID: "apple")
        guard case .globallyAllowed = allowed else {
            Issue.record("Expected .globallyAllowed, got \(allowed)")
            return
        }

        let denied = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/Library/Apple/XProtect", teamID: "TEAM")
        #expect(!denied.isAllowed)
    }

    // MARK: Global allowlist — mixed and multi-tier

    @Test("mixed allowlist — signing entry bypasses policy")
    func mixedAllowlistSigningBypasses() async {
        let allowlist = [
            AllowlistEntry(signingID: "com.apple.mdworker", platformBinary: true),
            AllowlistEntry(processPath: "/usr/libexec/custom-scanner"),
        ]
        let rules = [ruleProtecting("/protected")]
        let decision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/System/mdworker", teamID: "apple", signingID: "com.apple.mdworker")
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("mixed allowlist — path entry bypasses policy when signing doesn't match")
    func mixedAllowlistPathBypasses() async {
        let allowlist = [
            AllowlistEntry(signingID: "com.apple.mdworker", platformBinary: true),
            AllowlistEntry(processPath: "/usr/libexec/custom-scanner"),
        ]
        let rules = [ruleProtecting("/protected")]
        let decision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/usr/libexec/custom-scanner", teamID: "CUSTOM", signingID: "com.custom.scanner")
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("mixed allowlist — neither entry matches, falls through to policy")
    func mixedAllowlistNeitherMatchesFallsThrough() async {
        let allowlist = [
            AllowlistEntry(signingID: "com.apple.mdworker", platformBinary: true),
            AllowlistEntry(processPath: "/usr/libexec/custom-scanner"),
        ]
        let rules = [ruleProtecting("/protected")]
        let decision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/evil/binary", teamID: "EVIL", signingID: "com.evil")
        #expect(!decision.isAllowed)
    }

    @Test("multi-tier allowlist: baseline + managed + user entries")
    func multiTierAllowlist() async {
        let baseline = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        let managed = [AllowlistEntry(signingID: "com.corp.agent", teamID: "CORP88")]
        let user = [AllowlistEntry(processPath: "/usr/local/bin/dev-tool")]
        let allowlist = baseline + managed + user
        let rules = [ruleProtecting("/protected")]

        let finderDecision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/System/Finder", teamID: "apple", signingID: "com.apple.finder")
        guard case .globallyAllowed = finderDecision else {
            Issue.record("Expected Finder to be globally allowed")
            return
        }

        let corpDecision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/opt/corp/agent", teamID: "CORP88", signingID: "com.corp.agent")
        guard case .globallyAllowed = corpDecision else {
            Issue.record("Expected corp agent to be globally allowed")
            return
        }

        let devToolDecision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/usr/local/bin/dev-tool")
        guard case .globallyAllowed = devToolDecision else {
            Issue.record("Expected dev-tool to be globally allowed")
            return
        }

        let unknownDecision = await decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/unknown", teamID: "UNK", signingID: "com.unknown")
        #expect(!unknownDecision.isAllowed)
    }

    // MARK: Global allowlist bypasses policy completely

    @Test("allowlisted process bypasses even a deny-all rule")
    func allowlistBypassesDenyAll() async {
        let allowlist = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        let denyAllRule = FAARule(protectedPathPrefix: "/protected")
        let decision = await decide(rules: [denyAllRule], allowlist: allowlist, path: "/protected/file", processPath: "/System/Finder", teamID: "apple", signingID: "com.apple.finder")
        guard case .globallyAllowed = decision else {
            Issue.record("Allowlisted process should bypass deny-all rule")
            return
        }
    }

    @Test("non-allowlisted process hitting unprotected path is noRuleApplies")
    func nonAllowlistedUnprotectedPath() async {
        let allowlist = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        let rules = [ruleProtecting("/protected")]
        let decision = await decide(rules: rules, allowlist: allowlist, path: "/unprotected/file", processPath: "/usr/bin/cat", teamID: "TEAM", signingID: "com.cat")
        guard case .noRuleApplies = decision else {
            Issue.record("Expected .noRuleApplies, got \(decision)")
            return
        }
    }

    // MARK: Policy evaluation — no rule applies

    @Test("unprotected path is allowed by default")
    func unprotectedPathAllowed() async {
        let decision = await decide(rules: [ruleProtecting("/protected")], path: "/unprotected/file", processPath: "/bin/cat")
        #expect(decision.isAllowed)
        #expect(decision.matchedRuleID == nil)
    }

    @Test("empty rules and empty allowlist allows everything")
    func emptyRulesAndAllowlistAllowsAll() async {
        let decision = await decide(path: "/anything", processPath: "/anything")
        guard case .noRuleApplies = decision else {
            Issue.record("Expected .noRuleApplies, got \(decision)")
            return
        }
    }

    // MARK: Policy evaluation — allowed by process path

    @Test("allowed by process path in rule")
    func allowedByProcessPath() async {
        let rules = [ruleProtecting("/protected", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/usr/bin/safe")
        #expect(decision.isAllowed)
    }

    @Test("denied when process path not in rule's allowed list")
    func deniedWhenProcessPathNotAllowed() async {
        let rules = [ruleProtecting("/protected", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/usr/bin/evil")
        #expect(!decision.isAllowed)
        #expect(decision.matchedRuleID == ruleID)
    }

    // MARK: Policy evaluation — allowed by signature

    @Test("allowed by exact signature")
    func allowedByExactSignature() async {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/anything", teamID: "TEAM1", signingID: "com.example.app")
        #expect(decision.isAllowed)
    }

    @Test("allowed by wildcard signature")
    func allowedByWildcardSignature() async {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "*")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/anything", teamID: "TEAM1", signingID: "com.anything")
        #expect(decision.isAllowed)
    }

    @Test("Apple platform binary is allowed when teamID is apple")
    func applePlatformBinaryAllowed() async {
        let sig = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.finder")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/System/Finder", teamID: appleTeamID, signingID: "com.apple.finder")
        #expect(decision.isAllowed)
    }

    @Test("ad-hoc signed binary with Apple signing ID cannot spoof Apple identity in rules")
    func adhocBinaryCannotSpoofAppleIdentityInRules() async {
        let sig = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.finder")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/tmp/evil", teamID: "", signingID: "com.apple.finder")
        #expect(!decision.isAllowed)
    }

    @Test("denied when signature does not match")
    func deniedWhenSignatureMismatch() async {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/anything", teamID: "TEAM2", signingID: "com.evil")
        #expect(!decision.isAllowed)
    }

    // MARK: Policy evaluation — allowed by ancestor

    @Test("allowed by ancestor process path")
    func allowedByAncestorProcessPath() async {
        let rules = [ruleProtecting("/protected", allowedAncestorProcessPaths: ["/usr/bin/parent"])]
        let ancestors = [AncestorInfo(path: "/usr/bin/parent", teamID: "", signingID: "")]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/usr/bin/child", ancestors: ancestors)
        #expect(decision.isAllowed)
    }

    @Test("allowed by ancestor signature")
    func allowedByAncestorSignature() async {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "*")
        let rules = [ruleProtecting("/protected", allowedAncestorSignatures: [sig])]
        let ancestors = [AncestorInfo(path: "/some/parent", teamID: "TEAM1", signingID: "com.parent")]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/child", ancestors: ancestors)
        #expect(decision.isAllowed)
    }

    @Test("Apple platform binary ancestor is allowed when teamID is apple")
    func applePlatformBinaryAncestorAllowed() async {
        let sig = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.launchd")
        let rules = [ruleProtecting("/protected", allowedAncestorSignatures: [sig])]
        let ancestors = [AncestorInfo(path: "/sbin/launchd", teamID: "apple", signingID: "com.apple.launchd")]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/child", teamID: "SOMETEAM", signingID: "com.child", ancestors: ancestors)
        #expect(decision.isAllowed)
    }

    @Test("ad-hoc signed ancestor with Apple signing ID cannot spoof Apple identity in rules")
    func adhocAncestorCannotSpoofAppleIdentityInRules() async {
        let sig = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.launchd")
        let rules = [ruleProtecting("/protected", allowedAncestorSignatures: [sig])]
        let ancestors = [AncestorInfo(path: "/sbin/fake-launchd", teamID: "", signingID: "com.apple.launchd")]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/child", teamID: "SOMETEAM", signingID: "com.child", ancestors: ancestors)
        #expect(!decision.isAllowed)
    }

    @Test("denied when no ancestor matches")
    func deniedWhenNoAncestorMatches() async {
        let rules = [ruleProtecting("/protected", allowedAncestorProcessPaths: ["/usr/bin/parent"])]
        let ancestors = [AncestorInfo(path: "/usr/bin/other", teamID: "", signingID: "")]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/child", ancestors: ancestors)
        #expect(!decision.isAllowed)
    }

    // MARK: Policy evaluation — most specific path wins

    @Test("more specific rule wins regardless of array order")
    func moreSpecificRuleWins() async {
        let broadDeny = FAARule(protectedPathPrefix: "/protected")
        let specificAllow = FAARule(protectedPathPrefix: "/protected/sub", allowedProcessPaths: ["/usr/bin/safe"])
        let decision = await decide(
            rules: [broadDeny, specificAllow],
            path: "/protected/sub/file",
            processPath: "/usr/bin/safe"
        )
        #expect(decision.isAllowed)
    }

    @Test("equally specific rules — earlier allow beats later deny")
    func equalSpecificityAllowFirst() async {
        let allowRule = FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/usr/bin/safe"])
        let denyAllRule = FAARule(protectedPathPrefix: "/protected")
        let decision = await decide(rules: [allowRule, denyAllRule], path: "/protected/file", processPath: "/usr/bin/safe")
        #expect(decision.isAllowed)
    }

    @Test("equally specific rules — earlier deny beats later allow")
    func equalSpecificityDenyFirst() async {
        let denyAllRule = FAARule(protectedPathPrefix: "/protected")
        let allowRule = FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/usr/bin/safe"])
        let decision = await decide(rules: [denyAllRule, allowRule], path: "/protected/file", processPath: "/usr/bin/safe")
        #expect(!decision.isAllowed)
    }

    // MARK: Policy evaluation — deny reason

    @Test("deny reason includes rule and criteria")
    func denyReasonContent() async {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "com.allowed")
        let rules = [ruleProtecting("/secret", allowedSignatures: [sig])]
        let decision = await decide(rules: rules, path: "/secret/file", processPath: "/evil", teamID: "BAD", signingID: "com.evil")
        #expect(decision.reason.contains("/secret"))
        #expect(decision.reason.contains("TEAM1:com.allowed"))
    }

    // MARK: Policy evaluation — wildcard path rules

    @Test("wildcard rule protects matching paths")
    func wildcardRuleProtectsMatchingPaths() async {
        let rules = [ruleProtecting("/Users/*/Documents", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = await decide(rules: rules, path: "/Users/admin/Documents/secret.txt", processPath: "/usr/bin/evil")
        #expect(!decision.isAllowed)
    }

    @Test("wildcard rule allows matching process")
    func wildcardRuleAllowsMatchingProcess() async {
        let rules = [ruleProtecting("/Users/*/Documents", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = await decide(rules: rules, path: "/Users/admin/Documents/secret.txt", processPath: "/usr/bin/safe")
        #expect(decision.isAllowed)
    }

    @Test("wildcard rule does not apply to non-matching paths")
    func wildcardRuleIgnoresNonMatchingPaths() async {
        let rules = [ruleProtecting("/Users/*/Documents", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = await decide(rules: rules, path: "/Users/admin/Downloads/file.txt", processPath: "/usr/bin/evil")
        #expect(decision.isAllowed)
    }

    // MARK: Policy evaluation — multiple criteria

    @Test("process path checked before signature")
    func processPathCheckedFirst() async {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "*")
        let rules = [ruleProtecting("/protected", allowedProcessPaths: ["/usr/bin/safe"], allowedSignatures: [sig])]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/usr/bin/safe", teamID: "TEAM1", signingID: "com.x")
        #expect(decision.isAllowed)
        #expect(decision.reason.contains("process path"))
    }

    // MARK: Policy evaluation — write-only rules

    @Test("enforceOnWriteOnly rule allows reads from any process")
    func writeOnlyRuleAllowsReads() async {
        let rule = FAARule(
            id: ruleID,
            protectedPathPrefix: "/etc/pam.d",
            allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.opendirectoryd")],
            enforceOnWriteOnly: true
        )
        let decision = await decide(rules: [rule], path: "/etc/pam.d/sudo", processPath: "/bin/cat", accessKind: .read)
        guard case .noRuleApplies = decision else {
            Issue.record("Expected .noRuleApplies, got \(decision)")
            return
        }
    }

    @Test("enforceOnWriteOnly rule denies writes from non-allowed process")
    func writeOnlyRuleDeniesWrites() async {
        let rule = FAARule(
            id: ruleID,
            protectedPathPrefix: "/etc/pam.d",
            allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.opendirectoryd")],
            enforceOnWriteOnly: true
        )
        let decision = await decide(rules: [rule], path: "/etc/pam.d/sudo", processPath: "/bin/evil", accessKind: .write)
        #expect(!decision.isAllowed)
        #expect(decision.matchedRuleID == ruleID)
    }

    @Test("enforceOnWriteOnly rule allows writes from allowed process")
    func writeOnlyRuleAllowsAuthorisedWrites() async {
        let rule = FAARule(
            id: ruleID,
            protectedPathPrefix: "/etc/pam.d",
            allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.opendirectoryd")],
            enforceOnWriteOnly: true
        )
        let decision = await decide(
            rules: [rule],
            path: "/etc/pam.d/sudo",
            processPath: "/usr/libexec/opendirectoryd",
            teamID: appleTeamID,
            signingID: "com.apple.opendirectoryd",
            accessKind: .write
        )
        #expect(decision.isAllowed)
    }

    @Test("enforceOnWriteOnly skip falls through to later rule on same path for reads")
    func writeOnlyFallsThroughToLaterRule() async {
        // The write-only rule is skipped on a read event. The all-access
        // rule that follows IS evaluated and denies because /bin/cat is
        // not on its allow list. This pins the additive semantics —
        // write-only rules provide extra write-side protection without
        // disabling the read protection of later rules covering the
        // same path.
        let writeOnly = FAARule(
            id: UUID(),
            protectedPathPrefix: "/etc/pam.d",
            allowedSignatures: [ProcessSignature(teamID: appleTeamID, signingID: "com.apple.opendirectoryd")],
            enforceOnWriteOnly: true
        )
        let allAccess = FAARule(
            id: UUID(),
            protectedPathPrefix: "/etc/pam.d",
            allowedProcessPaths: ["/usr/libexec/opendirectoryd"]
        )
        let decision = await decide(
            rules: [writeOnly, allAccess],
            path: "/etc/pam.d/sudo",
            processPath: "/bin/cat",
            accessKind: .read
        )
        #expect(!decision.isAllowed)
    }

    // MARK: Policy evaluation — subpath read carve-out with universal wildcard

    @Test("universal wildcard carves out read-only subpath under a locked parent")
    func universalWildcardSubpathCarveOut() async {
        // Three rules implementing the SSH pattern from issue #130:
        //   1. Write-only rule on ~/.ssh/known_hosts (only sshd may write)
        //   2. Universal wildcard on ~/.ssh/known_hosts (any process may read)
        //   3. Full lock on ~/.ssh/ (only ssh/sshd may access)
        let sshd = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.sshd")
        let ssh  = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.ssh")
        let any  = ProcessSignature(teamID: "*", signingID: "*")

        let rules = [
            FAARule(id: UUID(), protectedPathPrefix: "/Users/*/.ssh/known_hosts",
                    allowedSignatures: [sshd], enforceOnWriteOnly: true),
            FAARule(id: UUID(), protectedPathPrefix: "/Users/*/.ssh/known_hosts",
                    allowedSignatures: [any]),
            FAARule(id: UUID(), protectedPathPrefix: "/Users/*/.ssh",
                    allowedSignatures: [ssh, sshd]),
        ]

        // Any process can READ known_hosts (rule 1 skipped, rule 2 wildcard allows)
        let readKnownHosts = await decide(
            rules: rules, path: "/Users/admin/.ssh/known_hosts",
            processPath: "/bin/cat", accessKind: .read
        )
        #expect(readKnownHosts.isAllowed)

        // Unauthorized process cannot WRITE known_hosts (rule 1 denies)
        let writeKnownHosts = await decide(
            rules: rules, path: "/Users/admin/.ssh/known_hosts",
            processPath: "/bin/evil", accessKind: .write
        )
        #expect(!writeKnownHosts.isAllowed)

        // sshd CAN write known_hosts (rule 1 allows)
        let sshdWriteKnownHosts = await decide(
            rules: rules, path: "/Users/admin/.ssh/known_hosts",
            processPath: "/usr/sbin/sshd", teamID: appleTeamID, signingID: "com.apple.sshd",
            accessKind: .write
        )
        #expect(sshdWriteKnownHosts.isAllowed)

        // Unauthorized process cannot READ id_rsa (rules 1+2 don't match, rule 3 denies)
        let readIdRsa = await decide(
            rules: rules, path: "/Users/admin/.ssh/id_rsa",
            processPath: "/bin/evil", accessKind: .read
        )
        #expect(!readIdRsa.isAllowed)
    }

    @Test("SSH carve-out works regardless of rule order")
    func sshCarveOutReversedOrder() async {
        let sshd = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.sshd")
        let ssh  = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.ssh")
        let any  = ProcessSignature(teamID: "*", signingID: "*")

        // Same three rules as universalWildcardSubpathCarveOut but REVERSED
        let rules = [
            FAARule(id: UUID(), protectedPathPrefix: "/Users/*/.ssh",
                    allowedSignatures: [ssh, sshd]),
            FAARule(id: UUID(), protectedPathPrefix: "/Users/*/.ssh/known_hosts",
                    allowedSignatures: [any]),
            FAARule(id: UUID(), protectedPathPrefix: "/Users/*/.ssh/known_hosts",
                    allowedSignatures: [sshd], enforceOnWriteOnly: true),
        ]

        let readKnownHosts = await decide(
            rules: rules, path: "/Users/admin/.ssh/known_hosts",
            processPath: "/bin/cat", accessKind: .read
        )
        #expect(readKnownHosts.isAllowed)

        let writeKnownHosts = await decide(
            rules: rules, path: "/Users/admin/.ssh/known_hosts",
            processPath: "/bin/evil", accessKind: .write
        )
        #expect(!writeKnownHosts.isAllowed)

        let sshdWriteKnownHosts = await decide(
            rules: rules, path: "/Users/admin/.ssh/known_hosts",
            processPath: "/usr/sbin/sshd", teamID: appleTeamID, signingID: "com.apple.sshd",
            accessKind: .write
        )
        #expect(sshdWriteKnownHosts.isAllowed)

        let readIdRsa = await decide(
            rules: rules, path: "/Users/admin/.ssh/id_rsa",
            processPath: "/bin/evil", accessKind: .read
        )
        #expect(!readIdRsa.isAllowed)
    }

    // MARK: Global ancestor allowlist

    private func decideWithAncestorAllowlist(
        rules: [FAARule] = [],
        allowlist: [AllowlistEntry] = [],
        ancestorAllowlist: [AncestorAllowlistEntry],
        path: String = "/protected/file",
        processPath: String = "/bin/test",
        teamID: String = "",
        signingID: String = "",
        accessKind: AccessKind = .write,
        ancestors: [AncestorInfo]
    ) async -> PolicyDecision {
        await evaluateAccess(
            rules: rules,
            allowlist: allowlist,
            ancestorAllowlist: ancestorAllowlist,
            path: path,
            process: ProcessFacts(processPath: processPath, teamID: teamID, signingID: signingID),
            responsibleProcess: .unknown,
            accessKind: accessKind,
            ancestryProvider: { ancestors },
            responsibleAncestryProvider: { [] }
        )
    }

    @Test("process with matching ancestor signing ID is globally allowed")
    func ancestorSigningIDGloballyAllowed() async {
        let ancestorEntry = AncestorAllowlistEntry(signingID: "com.apple.terminal", platformBinary: true)
        let rules = [ruleProtecting("/protected")]
        let ancestors = [AncestorInfo(path: "/Applications/Terminal.app/Contents/MacOS/Terminal", teamID: "apple", signingID: "com.apple.terminal")]
        let decision = await decideWithAncestorAllowlist(
            rules: rules, ancestorAllowlist: [ancestorEntry],
            processPath: "/usr/bin/cat", ancestors: ancestors
        )
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("process with matching ancestor path is globally allowed")
    func ancestorPathGloballyAllowed() async {
        let ancestorEntry = AncestorAllowlistEntry(processPath: "/usr/bin/bash")
        let rules = [ruleProtecting("/protected")]
        let ancestors = [AncestorInfo(path: "/usr/bin/bash", teamID: "", signingID: "")]
        let decision = await decideWithAncestorAllowlist(
            rules: rules, ancestorAllowlist: [ancestorEntry],
            processPath: "/usr/bin/cat", ancestors: ancestors
        )
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("process with non-matching ancestor falls through to policy")
    func nonMatchingAncestorFallsThrough() async {
        let ancestorEntry = AncestorAllowlistEntry(processPath: "/usr/bin/bash")
        let rules = [ruleProtecting("/protected")]
        let ancestors = [AncestorInfo(path: "/usr/bin/zsh", teamID: "", signingID: "")]
        let decision = await decideWithAncestorAllowlist(
            rules: rules, ancestorAllowlist: [ancestorEntry],
            processPath: "/usr/bin/cat", ancestors: ancestors
        )
        #expect(!decision.isAllowed)
    }

    @Test("process with empty ancestor chain and ancestor allowlist falls through to policy")
    func emptyAncestorChainFallsThrough() async {
        let ancestorEntry = AncestorAllowlistEntry(processPath: "/usr/bin/bash")
        let rules = [ruleProtecting("/protected")]
        let decision = await decideWithAncestorAllowlist(
            rules: rules, ancestorAllowlist: [ancestorEntry],
            processPath: "/usr/bin/cat", ancestors: []
        )
        #expect(!decision.isAllowed)
    }

    @Test("ancestor allowlist platform binary requires apple team ID")
    func ancestorPlatformBinaryRequiresAppleTeam() async {
        let ancestorEntry = AncestorAllowlistEntry(signingID: "com.apple.terminal", platformBinary: true)
        let rules = [ruleProtecting("/protected")]
        let ancestorWithTeam = AncestorInfo(path: "/Applications/Terminal.app/Contents/MacOS/Terminal", teamID: "SOMETEAM", signingID: "com.apple.terminal")
        let decision = await decideWithAncestorAllowlist(
            rules: rules, ancestorAllowlist: [ancestorEntry],
            processPath: "/usr/bin/cat", ancestors: [ancestorWithTeam]
        )
        #expect(!decision.isAllowed)
    }

    @Test("immediate process allowlist takes precedence over ancestor allowlist check")
    func immediateAllowlistTakesPrecedence() async {
        let immediateEntry = AllowlistEntry(signingID: "com.example.trusted", teamID: "TRUST1")
        let ancestorEntry = AncestorAllowlistEntry(processPath: "/usr/bin/bash")
        let rules = [ruleProtecting("/protected")]
        let decision = await decideWithAncestorAllowlist(
            rules: rules, allowlist: [immediateEntry], ancestorAllowlist: [ancestorEntry],
            processPath: "/anywhere", teamID: "TRUST1", signingID: "com.example.trusted",
            ancestors: []
        )
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed from immediate allowlist, got \(decision)")
            return
        }
    }

    @Test("ancestor allowlist bypasses deny-all rule when ancestor matches")
    func ancestorAllowlistBypassesDenyAll() async {
        let ancestorEntry = AncestorAllowlistEntry(processPath: "/usr/bin/bash")
        let denyAllRule = FAARule(protectedPathPrefix: "/protected")
        let ancestors = [AncestorInfo(path: "/usr/bin/bash", teamID: "", signingID: "")]
        let decision = await decideWithAncestorAllowlist(
            rules: [denyAllRule], ancestorAllowlist: [ancestorEntry],
            processPath: "/usr/bin/cat", ancestors: ancestors
        )
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("ancestor allowlist with team ID constraint — correct team is allowed")
    func ancestorTeamIDConstraintAllowed() async {
        let ancestorEntry = AncestorAllowlistEntry(signingID: "com.corp.tool", teamID: "CORP99")
        let rules = [ruleProtecting("/protected")]
        let ancestor = AncestorInfo(path: "/opt/corp/tool", teamID: "CORP99", signingID: "com.corp.tool")
        let decision = await decideWithAncestorAllowlist(
            rules: rules, ancestorAllowlist: [ancestorEntry],
            processPath: "/usr/bin/cat", ancestors: [ancestor]
        )
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("ancestor allowlist with team ID constraint — wrong team is denied")
    func ancestorTeamIDConstraintDenied() async {
        let ancestorEntry = AncestorAllowlistEntry(signingID: "com.corp.tool", teamID: "CORP99")
        let rules = [ruleProtecting("/protected")]
        let ancestor = AncestorInfo(path: "/opt/corp/tool", teamID: "EVIL11", signingID: "com.corp.tool")
        let decision = await decideWithAncestorAllowlist(
            rules: rules, ancestorAllowlist: [ancestorEntry],
            processPath: "/usr/bin/cat", ancestors: [ancestor]
        )
        #expect(!decision.isAllowed)
    }

    @Test("any ancestor in the chain matching is sufficient")
    func anyAncestorMatchSuffices() async {
        let ancestorEntry = AncestorAllowlistEntry(processPath: "/usr/bin/bash")
        let rules = [ruleProtecting("/protected")]
        let ancestors = [
            AncestorInfo(path: "/usr/bin/zsh", teamID: "", signingID: ""),
            AncestorInfo(path: "/usr/bin/bash", teamID: "", signingID: ""),
            AncestorInfo(path: "/sbin/launchd", teamID: "", signingID: ""),
        ]
        let decision = await decideWithAncestorAllowlist(
            rules: rules, ancestorAllowlist: [ancestorEntry],
            processPath: "/usr/bin/cat", ancestors: ancestors
        )
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed when one ancestor matches, got \(decision)")
            return
        }
    }
}

// MARK: - FAARule.requiresAncestry

@Suite("FAARule.requiresAncestry")
struct RequiresAncestryTests {
    @Test("rule with only process criteria does not require ancestry")
    func processOnlyRule() {
        let rule = FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/usr/bin/safe"])
        #expect(!rule.requiresAncestry)
    }

    @Test("rule with only signature criteria does not require ancestry")
    func signatureOnlyRule() {
        let rule = FAARule(protectedPathPrefix: "/protected", allowedSignatures: [ProcessSignature(teamID: "T", signingID: "*")])
        #expect(!rule.requiresAncestry)
    }

    @Test("rule with ancestor process paths requires ancestry")
    func ancestorPathsRule() {
        let rule = FAARule(protectedPathPrefix: "/protected", allowedAncestorProcessPaths: ["/usr/bin/parent"])
        #expect(rule.requiresAncestry)
    }

    @Test("rule with ancestor signatures requires ancestry")
    func ancestorSignaturesRule() {
        let rule = FAARule(protectedPathPrefix: "/protected", allowedAncestorSignatures: [ProcessSignature(teamID: "T", signingID: "*")])
        #expect(rule.requiresAncestry)
    }

    @Test("empty rule does not require ancestry")
    func emptyRule() {
        let rule = FAARule(protectedPathPrefix: "/protected")
        #expect(!rule.requiresAncestry)
    }
}

// MARK: - classifyPath

@Suite("classifyPath")
struct ClassifyPathTests {
    @Test("unprotected path returns noRuleApplies")
    func unprotectedPath() {
        let rules = [FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/safe"])]
        guard case .noRuleApplies = classifyPath("/unrelated/file", rules: rules) else {
            Issue.record("Expected .noRuleApplies")
            return
        }
    }

    @Test("path matching process-only rule returns processLevelOnly")
    func processOnlyRuleClassification() {
        let rules = [FAARule(protectedPathPrefix: "/protected", allowedSignatures: [ProcessSignature(teamID: "T", signingID: "*")])]
        guard case .processLevelOnly = classifyPath("/protected/file", rules: rules) else {
            Issue.record("Expected .processLevelOnly")
            return
        }
    }

    @Test("path matching ancestry rule returns ancestryRequired")
    func ancestryRuleClassification() {
        let rules = [FAARule(protectedPathPrefix: "/protected", allowedAncestorProcessPaths: ["/usr/bin/parent"])]
        guard case .ancestryRequired = classifyPath("/protected/file", rules: rules) else {
            Issue.record("Expected .ancestryRequired")
            return
        }
    }

    @Test("any matching rule requiring ancestry promotes to ancestryRequired")
    func anyMatchingAncestryPromotes() {
        let rules = [
            FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/safe"]),
            FAARule(protectedPathPrefix: "/protected", allowedAncestorProcessPaths: ["/parent"]),
        ]
        guard case .ancestryRequired = classifyPath("/protected/file", rules: rules) else {
            Issue.record("Expected .ancestryRequired because one matching rule requires ancestry")
            return
        }
    }

    @Test("empty rules returns noRuleApplies")
    func emptyRules() {
        guard case .noRuleApplies = classifyPath("/anything", rules: []) else {
            Issue.record("Expected .noRuleApplies")
            return
        }
    }
}

// MARK: - classifyPaths (dual-path)

@Suite("classifyPaths")
struct ClassifyPathsTests {
    @Test("nil secondary path delegates to single-path classifyPath")
    func nilSecondaryPath() {
        let rules = [FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/safe"])]
        guard case .noRuleApplies = classifyPaths("/unrelated/file", secondaryPath: nil, reach: .singlePath, rules: rules) else {
            Issue.record("Expected .noRuleApplies")
            return
        }
    }

    @Test("returns ancestryRequired when only secondary path is protected by ancestry rule")
    func secondaryPathProtectedByAncestryRule() {
        let rules = [FAARule(protectedPathPrefix: "/protected", allowedAncestorProcessPaths: ["/usr/bin/parent"])]
        guard case .ancestryRequired = classifyPaths("/unrelated/file", secondaryPath: "/protected/dest", reach: .singlePath, rules: rules) else {
            Issue.record("Expected .ancestryRequired")
            return
        }
    }

    @Test("returns most restrictive classification when both paths are protected")
    func mostRestrictiveClassification() {
        let rules = [
            FAARule(protectedPathPrefix: "/simple", allowedProcessPaths: ["/safe"]),
            FAARule(protectedPathPrefix: "/complex", allowedAncestorProcessPaths: ["/usr/bin/parent"]),
        ]
        guard case .ancestryRequired = classifyPaths("/simple/file", secondaryPath: "/complex/dest", reach: .singlePath, rules: rules) else {
            Issue.record("Expected .ancestryRequired from more restrictive secondary path")
            return
        }
    }

    @Test("returns processLevelOnly when secondary path is protected by process-level rule")
    func secondaryPathProcessLevelOnly() {
        let rules = [FAARule(protectedPathPrefix: "/protected", allowedSignatures: [ProcessSignature(teamID: "T", signingID: "*")])]
        guard case .processLevelOnly = classifyPaths("/unrelated/file", secondaryPath: "/protected/dest", reach: .singlePath, rules: rules) else {
            Issue.record("Expected .processLevelOnly")
            return
        }
    }
}

// MARK: - checkFAAPolicy (dual-path)

@Suite("checkFAAPolicy dual-path")
struct CheckFAAPolicyDualPathTests {
    @Test("denies when only secondary path is protected and process is not allowed")
    func deniesWhenSecondaryPathProtected() {
        let rules = [FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/allowed"])]
        let decision = checkFAAPolicy(
            rules: rules,
            path: "/unprotected/source",
            secondaryPath: "/protected/dest",
            reach: .singlePath,
            subject: PolicySubject(
                process: ProcessFacts(processPath: "/unauthorized", teamID: "", signingID: ""),
                ancestors: [],
                responsibleProcess: .unknown,
                responsibleAncestors: []
            ),
            accessKind: .write
        )
        #expect(!decision.isAllowed)
    }

    @Test("allows when secondary path is protected and process is allowed")
    func allowsWhenProcessAllowed() {
        let rules = [FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/allowed"])]
        let decision = checkFAAPolicy(
            rules: rules,
            path: "/unprotected/source",
            secondaryPath: "/protected/dest",
            reach: .singlePath,
            subject: PolicySubject(
                process: ProcessFacts(processPath: "/allowed", teamID: "", signingID: ""),
                ancestors: [],
                responsibleProcess: .unknown,
                responsibleAncestors: []
            ),
            accessKind: .write
        )
        #expect(decision.isAllowed)
    }

    @Test("denies when both paths are protected and process is not allowed for either")
    func deniesBothProtected() {
        let rules = [
            FAARule(protectedPathPrefix: "/src", allowedProcessPaths: ["/allowed"]),
            FAARule(protectedPathPrefix: "/dst", allowedProcessPaths: ["/allowed"]),
        ]
        let decision = checkFAAPolicy(
            rules: rules,
            path: "/src/file",
            secondaryPath: "/dst/file",
            reach: .singlePath,
            subject: PolicySubject(
                process: ProcessFacts(processPath: "/unauthorized", teamID: "", signingID: ""),
                ancestors: [],
                responsibleProcess: .unknown,
                responsibleAncestors: []
            ),
            accessKind: .write
        )
        #expect(!decision.isAllowed)
    }

    @Test("nil secondary path behaves like single-path check")
    func nilSecondaryPath() {
        let rules = [FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/allowed"])]
        let decision = checkFAAPolicy(
            rules: rules,
            path: "/unprotected/file",
            secondaryPath: nil,
            reach: .singlePath,
            subject: PolicySubject(
                process: ProcessFacts(processPath: "/unauthorized", teamID: "", signingID: ""),
                ancestors: [],
                responsibleProcess: .unknown,
                responsibleAncestors: []
            ),
            accessKind: .write
        )
        guard case .noRuleApplies = decision else {
            Issue.record("Expected .noRuleApplies")
            return
        }
    }
}

// MARK: - requireValidSigning

@Suite("FAARule.requireValidSigning")
struct RequireValidSigningTests {
    private let ruleID = UUID()

    private func rule(requireValidSigning: Bool, enforceOnWriteOnly: Bool = false) -> FAARule {
        FAARule(
            id: ruleID,
            protectedPathPrefix: "/protected",
            allowedSignatures: [ProcessSignature(teamID: "*", signingID: "*")],
            enforceOnWriteOnly: enforceOnWriteOnly,
            requireValidSigning: requireValidSigning
        )
    }

    private func decide(
        rules: [FAARule],
        teamID: String,
        accessKind: AccessKind = .write
    ) async -> PolicyDecision {
        await evaluateAccess(
            rules: rules,
            allowlist: [],
            path: "/protected/file",
            process: ProcessFacts(processPath: "/bin/test", teamID: teamID, signingID: ""),
            responsibleProcess: .unknown,
            accessKind: accessKind,
            ancestryProvider: { [] },
            responsibleAncestryProvider: { [] }
        )
    }

    @Test("requireValidSigning false: unsigned process with *:* wildcard is allowed")
    func unsignedAllowedWhenFlagOff() async {
        let decision = await decide(rules: [rule(requireValidSigning: false)], teamID: "")
        #expect(decision.isAllowed)
    }

    @Test("requireValidSigning true: unsigned process is denied")
    func unsignedDeniedWhenFlagOn() async {
        let decision = await decide(rules: [rule(requireValidSigning: true)], teamID: "")
        #expect(!decision.isAllowed)
        #expect(decision.matchedRuleID == ruleID)
    }

    @Test("requireValidSigning true: Apple platform binary is allowed")
    func applePlatformBinaryAllowed() async {
        let decision = await decide(rules: [rule(requireValidSigning: true)], teamID: appleTeamID)
        #expect(decision.isAllowed)
    }

    @Test("requireValidSigning true: third-party signed process is allowed")
    func thirdPartySignedAllowed() async {
        let decision = await decide(rules: [rule(requireValidSigning: true)], teamID: "ABC123")
        #expect(decision.isAllowed)
    }

    @Test("requireValidSigning true + enforceOnWriteOnly true: unsigned process reading is noRuleApplies")
    func writeOnlyRuleSkippedForReads() async {
        let writeOnlyRule = rule(requireValidSigning: true, enforceOnWriteOnly: true)
        let decision = await decide(rules: [writeOnlyRule], teamID: "", accessKind: .read)
        guard case .noRuleApplies = decision else {
            Issue.record("Expected .noRuleApplies — write-only rule must be skipped before requireValidSigning is checked")
            return
        }
    }
}

@Suite("subtree operations on parent directories")
struct SubtreeOperationTests {
    private let inMemoryCompatibilityRule = FAARule(
        protectedPathPrefix: "/private/var/folders/**/NSCreateObjectFileImageFromMemory-*",
        enforceOnWriteOnly: true,
        doubleStarParentMatching: .stopAtDoubleStar
    )

    @Test("compatibility rule does not cover a directory below the double-star")
    func compatibilityRuleIgnoresDirectoryBelowDoubleStar() {
        let decision = decide(rules: [inMemoryCompatibilityRule], path: "/private/var/folders/zz/abc/T/TemporaryItems", secondaryPath: "/private/var/folders/zz/abc/T/TemporaryItems2")
        guard case .noRuleApplies = decision else {
            Issue.record("Expected .noRuleApplies, got \(decision)")
            return
        }
    }

    @Test("compatibility rule still covers a directory above the double-star")
    func compatibilityRuleCoversDirectoryAboveDoubleStar() {
        let decision = decide(rules: [inMemoryCompatibilityRule], path: "/private/var", secondaryPath: "/private/var2")
        #expect(!decision.isAllowed)
    }

    @Test("classifyPaths ignores a directory below the double-star for a compatibility rule")
    func classifyPathsIgnoresDirectoryBelowDoubleStarForCompatibilityRule() {
        guard case .noRuleApplies = classifyPaths("/private/var/folders/zz/abc", secondaryPath: nil, reach: .subtree, rules: [inMemoryCompatibilityRule]) else {
            Issue.record("Expected .noRuleApplies")
            return
        }
    }

    private let goalRule = FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedProcessPaths: ["/Applications/Goal.app/Contents/MacOS/Goal"])

    private func decide(
        rules: [FAARule],
        allowlist: [AllowlistEntry] = [],
        path: String,
        secondaryPath: String? = nil,
        reach: OperationReach = .subtree,
        processPath: String = "/tmp/poc",
        teamID: String = "",
        signingID: String = "",
        accessKind: AccessKind = .write
    ) -> PolicyDecision {
        evaluateAccess(
            rules: rules,
            allowlist: allowlist,
            path: path,
            secondaryPath: secondaryPath,
            reach: reach,
            subject: PolicySubject(
                process: ProcessFacts(processPath: processPath, teamID: teamID, signingID: signingID),
                ancestors: [],
                responsibleProcess: .unknown,
                responsibleAncestors: []
            ),
            accessKind: accessKind
        )
    }

    @Test("clone of the directory that holds protected files is denied")
    func cloneOfProtectedDirectoryIsDenied() {
        let decision = decide(rules: [goalRule], path: "/Users/develop/goal", secondaryPath: "/private/tmp/ck_clone_out")
        #expect(!decision.isAllowed)
    }

    @Test("rename swap onto the protected directory is denied")
    func renameSwapOntoProtectedDirectoryIsDenied() {
        let decision = decide(rules: [goalRule], path: "/Users/develop/evildir", secondaryPath: "/Users/develop/goal")
        #expect(!decision.isAllowed)
    }

    @Test("rename of the protected directory itself is denied")
    func renameOfProtectedDirectoryIsDenied() {
        let decision = decide(rules: [goalRule], path: "/Users/develop/goal", secondaryPath: "/Users/develop/goal2")
        #expect(!decision.isAllowed)
    }

    @Test("rename of a grandparent is denied")
    func renameOfGrandparentIsDenied() {
        let decision = decide(rules: [goalRule], path: "/Users/develop", secondaryPath: "/Users/develop2")
        #expect(!decision.isAllowed)
    }

    @Test("rename of an unrelated sibling directory is not covered by any rule")
    func renameOfUnrelatedSiblingIsAllowed() {
        let decision = decide(rules: [goalRule], path: "/Users/develop/other", secondaryPath: "/Users/develop/other2")
        guard case .noRuleApplies = decision else {
            Issue.record("Expected .noRuleApplies, got \(decision)")
            return
        }
    }

    @Test("single-path operation on the parent directory is not covered by any rule")
    func singlePathOperationOnParentIsUnchanged() {
        let decision = decide(rules: [goalRule], path: "/Users/develop/goal", reach: .singlePath)
        guard case .noRuleApplies = decision else {
            Issue.record("Expected .noRuleApplies, got \(decision)")
            return
        }
    }

    @Test("process allowed by every rule beneath is allowed")
    func processAllowedByEveryRuleBeneathIsAllowed() {
        let decision = decide(rules: [goalRule], path: "/Users/develop/goal", secondaryPath: "/Users/develop/goal.old", processPath: "/Applications/Goal.app/Contents/MacOS/Goal")
        #expect(decision.isAllowed)
    }

    @Test("process allowed by only one of two rules beneath is denied")
    func processAllowedByOneOfTwoRulesIsDenied() {
        let otherRule = FAARule(protectedPathPrefix: "/Users/develop/vault", allowedProcessPaths: ["/Applications/Vault.app/Contents/MacOS/Vault"])
        let decision = decide(rules: [goalRule, otherRule], path: "/Users/develop", secondaryPath: "/Users/develop2", processPath: "/Applications/Goal.app/Contents/MacOS/Goal")
        #expect(!decision.isAllowed)
    }

    @Test("subtree operation is evaluated as a write for write-only rules")
    func subtreeOperationIsWriteForWriteOnlyRules() {
        let writeOnly = FAARule(protectedPathPrefix: "/Users/*/.ssh", allowedSignatures: [ProcessSignature(teamID: "apple", signingID: "com.apple.ssh-agent")], enforceOnWriteOnly: true)
        let decision = decide(rules: [writeOnly], path: "/Users/develop", secondaryPath: "/Users/develop2", accessKind: .read)
        #expect(!decision.isAllowed)
    }

    @Test("rename under a double-star rule is checked")
    func renameUnderDoubleStarRuleIsChecked() {
        let rule = FAARule(protectedPathPrefix: "/a/**/secret")
        let decision = decide(rules: [rule], path: "/a/b/c", secondaryPath: "/a/b/d")
        #expect(!decision.isAllowed)
    }

    @Test("globally allowed process may rename a parent")
    func globallyAllowedProcessMayRenameParent() {
        let allowlist = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        let decision = decide(rules: [goalRule], allowlist: allowlist, path: "/Users/develop", secondaryPath: "/Users/develop2", teamID: "apple", signingID: "com.apple.finder")
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("classifyPaths reports a rule for a subtree operation on a parent")
    func classifyPathsReportsRuleForParent() {
        guard case .processLevelOnly = classifyPaths("/Users/develop/goal", secondaryPath: "/private/tmp/out", reach: .subtree, rules: [goalRule]) else {
            Issue.record("Expected .processLevelOnly")
            return
        }
    }

    @Test("classifyPaths requires ancestry when a rule beneath needs it")
    func classifyPathsRequiresAncestryForRuleBeneath() {
        let ancestryRule = FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedAncestorProcessPaths: ["/usr/bin/parent"])
        guard case .ancestryRequired = classifyPaths("/Users/develop", secondaryPath: nil, reach: .subtree, rules: [ancestryRule]) else {
            Issue.record("Expected .ancestryRequired")
            return
        }
    }

    @Test("classifyPaths ignores parents for a single-path operation")
    func classifyPathsIgnoresParentsForSinglePath() {
        guard case .noRuleApplies = classifyPaths("/Users/develop/goal", secondaryPath: nil, reach: .singlePath, rules: [goalRule]) else {
            Issue.record("Expected .noRuleApplies")
            return
        }
    }

    private let authorizationRule = FAARule(protectedPathPrefix: "/Users/develop/goal/*", requiresAuthorization: true)
    private let denyingRule = FAARule(protectedPathPrefix: "/Users/develop/vault", allowedProcessPaths: ["/Applications/Vault.app/Contents/MacOS/Vault"])

    @Test("denying rule beneath wins over a rule that requires authorization")
    func denyingRuleBeneathWinsOverAuthorizationRule() {
        let decision = decide(rules: [authorizationRule, denyingRule], path: "/Users/develop", secondaryPath: "/Users/develop2", teamID: "TEAM")
        guard case .denied = decision else {
            Issue.record("Expected .denied, got \(decision)")
            return
        }
    }

    @Test("denying rule beneath wins when listed before the authorization rule")
    func denyingRuleListedFirstWinsOverAuthorizationRule() {
        let decision = decide(rules: [denyingRule, authorizationRule], path: "/Users/develop", secondaryPath: "/Users/develop2", teamID: "TEAM")
        guard case .denied = decision else {
            Issue.record("Expected .denied, got \(decision)")
            return
        }
    }

    @Test("denying rule beneath wins over authorization required by the path itself")
    func denyingRuleBeneathWinsOverAuthorizationOnPath() {
        let pathRule = FAARule(protectedPathPrefix: "/Users/develop/*", requiresAuthorization: true)
        let beneathRule = FAARule(protectedPathPrefix: "/Users/develop/goal/vault", allowedProcessPaths: ["/Applications/Vault.app/Contents/MacOS/Vault"])
        let decision = decide(rules: [pathRule, beneathRule], path: "/Users/develop/goal", secondaryPath: "/Users/develop/goal2", teamID: "TEAM")
        guard case .denied = decision else {
            Issue.record("Expected .denied, got \(decision)")
            return
        }
    }
}

// MARK: - Baseline allowlist and Spotlight indexers

@Suite("baselineAllowlist Spotlight indexers")
struct BaselineAllowlistSpotlightTests {
    @Test("indexer is not on the baseline allowlist", arguments: spotlightIndexerSigningIDs)
    func indexerIsNotOnBaselineAllowlist(signingID: String) {
        #expect(!isGloballyAllowed(allowlist: baselineAllowlist, processPath: "/System/indexer", signingID: signingID, teamID: "apple"))
    }

    @Test("indexer reading a protected file is denied", arguments: spotlightIndexerSigningIDs)
    func indexerReadingProtectedFileIsDenied(signingID: String) async {
        let rules = [FAARule(protectedPathPrefix: "/Users/develop/goal/*")]

        let decision = await evaluateAccess(
            rules: rules,
            allowlist: baselineAllowlist,
            path: "/Users/develop/goal/gold",
            process: ProcessFacts(processPath: "/System/indexer", teamID: "apple", signingID: signingID),
            responsibleProcess: .unknown,
            accessKind: .read,
            ancestryProvider: { [] },
            responsibleAncestryProvider: { [] }
        )

        guard case .denied = decision else {
            Issue.record("Expected .denied, got \(decision)")
            return
        }
    }

    @Test("indexer reading an unprotected file is allowed")
    func indexerReadingUnprotectedFileIsAllowed() async {
        let rules = [FAARule(protectedPathPrefix: "/Users/develop/goal/*")]

        let decision = await evaluateAccess(
            rules: rules,
            allowlist: baselineAllowlist,
            path: "/Users/develop/Documents/notes.txt",
            process: ProcessFacts(processPath: "/System/indexer", teamID: "apple", signingID: "com.apple.mdworker_shared"),
            responsibleProcess: .unknown,
            accessKind: .read,
            ancestryProvider: { [] },
            responsibleAncestryProvider: { [] }
        )

        guard case .noRuleApplies = decision else {
            Issue.record("Expected .noRuleApplies, got \(decision)")
            return
        }
    }

    @Test("rule that allows the indexer still allows it")
    func ruleThatAllowsIndexerStillAllowsIt() async {
        let rules = [FAARule(
            protectedPathPrefix: "/Users/develop/goal/*",
            allowedSignatures: [ProcessSignature(teamID: "apple", signingID: "com.apple.mdworker_shared")]
        )]

        let decision = await evaluateAccess(
            rules: rules,
            allowlist: baselineAllowlist,
            path: "/Users/develop/goal/gold",
            process: ProcessFacts(processPath: "/System/indexer", teamID: "apple", signingID: "com.apple.mdworker_shared"),
            responsibleProcess: .unknown,
            accessKind: .read,
            ancestryProvider: { [] },
            responsibleAncestryProvider: { [] }
        )

        guard case .allowed = decision else {
            Issue.record("Expected .allowed, got \(decision)")
            return
        }
    }
}

// MARK: - Responsible process checks

@Suite("Responsible process checks")
struct ResponsibleProcessCheckTests {
    private let goldPath = "/Users/develop/goal/gold"
    private let networkingFacts = ProcessFacts(
        processPath: "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking",
        teamID: appleTeamID,
        signingID: "com.apple.WebKit.Networking"
    )
    private let safariFacts = ProcessFacts(
        processPath: "/Applications/Safari.app/Contents/MacOS/Safari",
        teamID: appleTeamID,
        signingID: "com.apple.Safari"
    )
    private let adHocToolFacts = ProcessFacts(
        processPath: "/tmp/ck-poc",
        teamID: "",
        signingID: "ck-poc"
    )
    private let safariSignature = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.Safari")
    private let networkingSignature = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.WebKit.Networking")

    private var safariOnlyRule: FAARule {
        FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedSignatures: [safariSignature])
    }

    private func subject(
        process: ProcessFacts,
        responsibleProcess: ResponsibleProcess,
        ancestors: [AncestorInfo] = [],
        responsibleAncestors: [AncestorInfo] = []
    ) -> PolicySubject {
        PolicySubject(
            process: process,
            ancestors: ancestors,
            responsibleProcess: responsibleProcess,
            responsibleAncestors: responsibleAncestors
        )
    }

    @Test("Networking process with a Safari responsible process is checked as Safari and allowed")
    func networkingWithSafariResponsibleIsAllowed() {
        let decision = checkFAAPolicy(
            rules: [safariOnlyRule],
            path: goldPath,
            subject: subject(process: networkingFacts, responsibleProcess: .known(safariFacts)),
            accessKind: .read
        )

        guard case .allowed(_, _, _, _, let checkedProcess) = decision else {
            Issue.record("Expected .allowed, got \(decision)")
            return
        }
        #expect(checkedProcess == .responsible(safariFacts))
    }

    @Test("Networking process with an ad-hoc tool as responsible process is denied")
    func networkingWithAdHocResponsibleIsDenied() {
        let decision = checkFAAPolicy(
            rules: [safariOnlyRule],
            path: goldPath,
            subject: subject(process: networkingFacts, responsibleProcess: .known(adHocToolFacts)),
            accessKind: .read
        )

        guard case .denied(_, _, _, _, let checkedProcess) = decision else {
            Issue.record("Expected .denied, got \(decision)")
            return
        }
        #expect(checkedProcess == .responsible(adHocToolFacts))
    }

    @Test("Networking process with an unknown responsible process is denied")
    func networkingWithUnknownResponsibleIsDenied() {
        let decision = checkFAAPolicy(
            rules: [safariOnlyRule],
            path: goldPath,
            subject: subject(process: networkingFacts, responsibleProcess: .unknown),
            accessKind: .read
        )

        guard case .denied(_, _, _, _, let checkedProcess) = decision else {
            Issue.record("Expected .denied, got \(decision)")
            return
        }
        #expect(checkedProcess == .unknownResponsible)
    }

    @Test("rule with an empty responsibleProcessChecks list checks the Networking process itself")
    func emptyResponsibleProcessChecksChecksItself() {
        let rule = FAARule(
            protectedPathPrefix: "/Users/develop/goal/*",
            allowedSignatures: [networkingSignature],
            responsibleProcessChecks: []
        )

        let decision = checkFAAPolicy(
            rules: [rule],
            path: goldPath,
            subject: subject(process: networkingFacts, responsibleProcess: .known(adHocToolFacts)),
            accessKind: .read
        )

        guard case .allowed(_, _, _, _, let checkedProcess) = decision else {
            Issue.record("Expected .allowed, got \(decision)")
            return
        }
        #expect(checkedProcess == .itself)
    }

    @Test("non-Apple process with a WebKit signing ID is checked as itself")
    func nonAppleProcessWithWebKitSigningIDIsCheckedAsItself() {
        let impostorFacts = ProcessFacts(
            processPath: "/tmp/com.apple.WebKit.Networking",
            teamID: "ABCDE12345",
            signingID: "com.apple.WebKit.Networking"
        )

        let decision = checkFAAPolicy(
            rules: [safariOnlyRule],
            path: goldPath,
            subject: subject(process: impostorFacts, responsibleProcess: .known(safariFacts)),
            accessKind: .read
        )

        guard case .denied(_, _, _, _, let checkedProcess) = decision else {
            Issue.record("Expected .denied, got \(decision)")
            return
        }
        #expect(checkedProcess == .itself)
    }

    @Test("ancestor criteria use the ancestors of the responsible process")
    func ancestorCriteriaUseResponsibleAncestors() {
        let terminalSignature = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.Terminal")
        let rule = FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedAncestorSignatures: [terminalSignature])
        let terminal = AncestorInfo(path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", teamID: appleTeamID, signingID: "com.apple.Terminal", uid: 501, gid: 20)
        let launchd = AncestorInfo(path: "/sbin/launchd", teamID: appleTeamID, signingID: "com.apple.xpc.launchd", uid: 0, gid: 0)

        let decision = checkFAAPolicy(
            rules: [rule],
            path: goldPath,
            subject: subject(
                process: networkingFacts,
                responsibleProcess: .known(safariFacts),
                ancestors: [launchd],
                responsibleAncestors: [terminal, launchd]
            ),
            accessKind: .read
        )

        guard case .allowed(_, _, _, _, let checkedProcess) = decision else {
            Issue.record("Expected .allowed, got \(decision)")
            return
        }
        #expect(checkedProcess == .responsible(safariFacts))
    }

    @Test("async overload gives responsible ancestors to an ancestor rule")
    func asyncOverloadUsesResponsibleAncestryProvider() async {
        let terminalSignature = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.Terminal")
        let rule = FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedAncestorSignatures: [terminalSignature])
        let terminal = AncestorInfo(path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", teamID: appleTeamID, signingID: "com.apple.Terminal", uid: 501, gid: 20)

        let decision = await checkFAAPolicy(
            rules: [rule],
            path: goldPath,
            process: networkingFacts,
            responsibleProcess: .known(safariFacts),
            accessKind: .read,
            ancestryProvider: { [] },
            responsibleAncestryProvider: { [terminal] }
        )

        #expect(decision.isAllowed)
        #expect(decision.checkedProcess == .responsible(safariFacts))
    }

    @Test("async overload does not call the responsible ancestry provider when the rule checks the process itself")
    func asyncOverloadSkipsResponsibleAncestryForItself() async {
        let terminalSignature = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.Terminal")
        let rule = FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedAncestorSignatures: [terminalSignature])
        let responsibleProviderCalls = OSAllocatedUnfairLock(initialState: 0)

        _ = await checkFAAPolicy(
            rules: [rule],
            path: goldPath,
            process: adHocToolFacts,
            responsibleProcess: .known(safariFacts),
            accessKind: .read,
            ancestryProvider: { [] },
            responsibleAncestryProvider: {
                responsibleProviderCalls.withLock { $0 += 1 }
                return []
            }
        )

        #expect(responsibleProviderCalls.withLock { $0 } == 0)
    }

    @Test("directory rename by the Networking process keeps the responsible process on the decision")
    func subtreeReachKeepsResponsibleCheckedProcess() {
        let decision = evaluateAccess(
            rules: [safariOnlyRule],
            allowlist: [],
            path: "/Users/develop/goal",
            secondaryPath: "/private/tmp/ck_clone_out",
            reach: .subtree,
            subject: subject(process: networkingFacts, responsibleProcess: .known(adHocToolFacts)),
            accessKind: .write
        )

        guard case .denied(_, _, _, _, let checkedProcess) = decision else {
            Issue.record("Expected .denied, got \(decision)")
            return
        }
        #expect(checkedProcess == .responsible(adHocToolFacts))
    }

    @Test("unknown responsible process is denied by a rule that allows *:*")
    func unknownResponsibleIsDeniedByWildcardAllowedSignature() {
        let rule = FAARule(
            protectedPathPrefix: "/Users/develop/goal/*",
            allowedSignatures: [ProcessSignature(teamID: "*", signingID: "*")]
        )

        let decision = checkFAAPolicy(
            rules: [rule],
            path: goldPath,
            subject: subject(process: networkingFacts, responsibleProcess: .unknown),
            accessKind: .read
        )

        guard case .denied(_, _, _, _, let checkedProcess) = decision else {
            Issue.record("Expected .denied, got \(decision)")
            return
        }
        #expect(checkedProcess == .unknownResponsible)
    }

    @Test("unknown responsible process is denied without a Touch ID prompt by a rule that authorizes *:*")
    func unknownResponsibleIsDeniedByWildcardAuthorizedSignature() {
        let rule = FAARule(
            protectedPathPrefix: "/Users/develop/goal/*",
            authorizedSignatures: [ProcessSignature(teamID: "*", signingID: "*")]
        )

        let decision = checkFAAPolicy(
            rules: [rule],
            path: goldPath,
            subject: subject(process: networkingFacts, responsibleProcess: .unknown),
            accessKind: .read
        )

        guard case .denied(_, _, _, _, let checkedProcess) = decision else {
            Issue.record("Expected .denied, got \(decision)")
            return
        }
        #expect(checkedProcess == .unknownResponsible)
    }

    @Test("unknown responsible process is denied by a rule that requires valid signing")
    func unknownResponsibleIsDeniedByRequireValidSigning() {
        let rule = FAARule(
            protectedPathPrefix: "/Users/develop/goal/*",
            allowedSignatures: [safariSignature],
            requireValidSigning: true
        )

        let decision = checkFAAPolicy(
            rules: [rule],
            path: goldPath,
            subject: subject(process: networkingFacts, responsibleProcess: .unknown),
            accessKind: .read
        )

        guard case .denied(_, _, _, _, let checkedProcess) = decision else {
            Issue.record("Expected .denied, got \(decision)")
            return
        }
        #expect(checkedProcess == .unknownResponsible)
    }

    @Test("ad-hoc process with a WebKit signing ID is checked as itself")
    func adHocProcessWithWebKitSigningIDIsCheckedAsItself() {
        let adHocImpostorFacts = ProcessFacts(
            processPath: "/tmp/com.apple.WebKit.Networking",
            teamID: "",
            signingID: "com.apple.WebKit.Networking"
        )

        let decision = checkFAAPolicy(
            rules: [safariOnlyRule],
            path: goldPath,
            subject: subject(process: adHocImpostorFacts, responsibleProcess: .known(safariFacts)),
            accessKind: .read
        )

        guard case .denied(_, _, _, _, let checkedProcess) = decision else {
            Issue.record("Expected .denied, got \(decision)")
            return
        }
        #expect(checkedProcess == .itself)
    }

    @Test("async overload does not call the process ancestry provider when only responsible ancestors are needed")
    func asyncOverloadSkipsProcessAncestryForResponsibleCheck() async {
        let terminalSignature = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.Terminal")
        let rule = FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedAncestorSignatures: [terminalSignature])
        let processProviderCalls = OSAllocatedUnfairLock(initialState: 0)

        _ = await checkFAAPolicy(
            rules: [rule],
            path: goldPath,
            process: networkingFacts,
            responsibleProcess: .known(safariFacts),
            accessKind: .read,
            ancestryProvider: {
                processProviderCalls.withLock { $0 += 1 }
                return []
            },
            responsibleAncestryProvider: { [] }
        )

        #expect(processProviderCalls.withLock { $0 } == 0)
    }

    @Test("async overload does not call the responsible ancestry provider when the responsible process is unknown")
    func asyncOverloadSkipsResponsibleAncestryForUnknownResponsible() async {
        let terminalSignature = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.Terminal")
        let rule = FAARule(protectedPathPrefix: "/Users/develop/goal/*", allowedAncestorSignatures: [terminalSignature])
        let responsibleProviderCalls = OSAllocatedUnfairLock(initialState: 0)

        _ = await checkFAAPolicy(
            rules: [rule],
            path: goldPath,
            process: networkingFacts,
            responsibleProcess: .unknown,
            accessKind: .read,
            ancestryProvider: { [] },
            responsibleAncestryProvider: {
                responsibleProviderCalls.withLock { $0 += 1 }
                return []
            }
        )

        #expect(responsibleProviderCalls.withLock { $0 } == 0)
    }
}
