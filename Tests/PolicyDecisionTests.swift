//
//  PolicyDecisionTests.swift
//  clearancekit
//

import Testing
import Foundation

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
            processPath: processPath,
            teamID: teamID,
            signingID: signingID,
            accessKind: accessKind,
            ancestryProvider: { ancestors }
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

    @Test("Apple platform binary gets resolved team ID in policy")
    func applePlatformBinaryResolution() async {
        let sig = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.finder")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/System/Finder", signingID: "com.apple.finder")
        #expect(decision.isAllowed)
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

    @Test("ancestor with empty team ID resolved to apple")
    func ancestorAppleResolution() async {
        let sig = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.launchd")
        let rules = [ruleProtecting("/protected", allowedAncestorSignatures: [sig])]
        let ancestors = [AncestorInfo(path: "/sbin/launchd", teamID: "", signingID: "com.apple.launchd")]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/child", teamID: "SOMETEAM", signingID: "com.child", ancestors: ancestors)
        #expect(decision.isAllowed)
    }

    @Test("denied when no ancestor matches")
    func deniedWhenNoAncestorMatches() async {
        let rules = [ruleProtecting("/protected", allowedAncestorProcessPaths: ["/usr/bin/parent"])]
        let ancestors = [AncestorInfo(path: "/usr/bin/other", teamID: "", signingID: "")]
        let decision = await decide(rules: rules, path: "/protected/file", processPath: "/child", ancestors: ancestors)
        #expect(!decision.isAllowed)
    }

    // MARK: Policy evaluation — first match wins

    @Test("first matching rule wins — earlier allow beats later deny")
    func firstRuleWins() async {
        let allowRule = FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/usr/bin/safe"])
        let denyAllRule = FAARule(protectedPathPrefix: "/protected")
        let decision = await decide(rules: [allowRule, denyAllRule], path: "/protected/file", processPath: "/usr/bin/safe")
        #expect(decision.isAllowed)
    }

    @Test("first matching rule wins — earlier deny beats later allow")
    func firstDenyWins() async {
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
            teamID: "",
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
            processPath: processPath,
            teamID: teamID,
            signingID: signingID,
            accessKind: accessKind,
            ancestryProvider: { ancestors }
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

    @Test("first-match-wins — earlier process-only rule takes precedence")
    func firstMatchWins() {
        let rules = [
            FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/safe"]),
            FAARule(protectedPathPrefix: "/protected", allowedAncestorProcessPaths: ["/parent"]),
        ]
        guard case .processLevelOnly = classifyPath("/protected/file", rules: rules) else {
            Issue.record("Expected .processLevelOnly from first matching rule")
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
        guard case .noRuleApplies = classifyPaths("/unrelated/file", secondaryPath: nil, rules: rules) else {
            Issue.record("Expected .noRuleApplies")
            return
        }
    }

    @Test("returns ancestryRequired when only secondary path is protected by ancestry rule")
    func secondaryPathProtectedByAncestryRule() {
        let rules = [FAARule(protectedPathPrefix: "/protected", allowedAncestorProcessPaths: ["/usr/bin/parent"])]
        guard case .ancestryRequired = classifyPaths("/unrelated/file", secondaryPath: "/protected/dest", rules: rules) else {
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
        guard case .ancestryRequired = classifyPaths("/simple/file", secondaryPath: "/complex/dest", rules: rules) else {
            Issue.record("Expected .ancestryRequired from more restrictive secondary path")
            return
        }
    }

    @Test("returns processLevelOnly when secondary path is protected by process-level rule")
    func secondaryPathProcessLevelOnly() {
        let rules = [FAARule(protectedPathPrefix: "/protected", allowedSignatures: [ProcessSignature(teamID: "T", signingID: "*")])]
        guard case .processLevelOnly = classifyPaths("/unrelated/file", secondaryPath: "/protected/dest", rules: rules) else {
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
            processPath: "/unauthorized",
            teamID: "",
            signingID: "",
            accessKind: .write,
            ancestors: []
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
            processPath: "/allowed",
            teamID: "",
            signingID: "",
            accessKind: .write,
            ancestors: []
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
            processPath: "/unauthorized",
            teamID: "",
            signingID: "",
            accessKind: .write,
            ancestors: []
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
            processPath: "/unauthorized",
            teamID: "",
            signingID: "",
            accessKind: .write,
            ancestors: []
        )
        guard case .noRuleApplies = decision else {
            Issue.record("Expected .noRuleApplies")
            return
        }
    }
}
