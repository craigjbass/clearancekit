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

// MARK: - mutePath

@Suite("mutePath")
struct MutePathTests {
    @Test("literal path unchanged")
    func literalPath() {
        #expect(mutePath(for: "/Library/Application Support/clearancekit") == "/Library/Application Support/clearancekit")
    }

    @Test("stops at first wildcard component")
    func stopsAtWildcard() {
        #expect(mutePath(for: "/Users/*/Documents") == "/Users")
    }

    @Test("double-star stops correctly")
    func doubleStarStops() {
        #expect(mutePath(for: "/a/**/file.txt") == "/a")
    }

    @Test("wildcard at root returns /")
    func wildcardAtRoot() {
        #expect(mutePath(for: "/*") == "/")
    }

    @Test("question mark stops correctly")
    func questionMarkStops() {
        #expect(mutePath(for: "/data/v?/file") == "/data")
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
        #expect(entry.matches(processPath: "/anything", signingID: "com.apple.finder", teamID: ""))
    }

    @Test("signing ID mismatch")
    func signingIDMismatch() {
        let entry = AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)
        #expect(!entry.matches(processPath: "/anything", signingID: "com.apple.safari", teamID: ""))
    }

    @Test("platform binary requires empty team ID")
    func platformBinaryRequiresEmptyTeamID() {
        let entry = AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)
        #expect(!entry.matches(processPath: "/anything", signingID: "com.apple.finder", teamID: "SOMETEAM"))
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

    @Test("path-based entry with platform binary flag requires empty team")
    func pathBasedPlatformBinary() {
        let entry = AllowlistEntry(processPath: "/Library/Apple/XProtect", platformBinary: true)
        #expect(entry.matches(processPath: "/Library/Apple/XProtect", signingID: "", teamID: ""))
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
        ancestors: [AncestorInfo] = []
    ) -> PolicyDecision {
        evaluateAccess(
            rules: rules,
            allowlist: allowlist,
            path: path,
            processPath: processPath,
            teamID: teamID,
            signingID: signingID,
            ancestors: ancestors
        )
    }

    // MARK: Global allowlist — signing-based

    @Test("platform binary on allowlist is globally allowed")
    func platformBinaryGloballyAllowed() {
        let allowlist = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        let rules = [ruleProtecting("/protected")]
        let decision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/System/Finder", signingID: "com.apple.finder")
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("platform binary with non-empty team ID is not globally allowed")
    func platformBinaryWrongTeamNotAllowed() {
        let allowlist = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        let rules = [ruleProtecting("/protected")]
        let decision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/anything", teamID: "SOMETEAM", signingID: "com.apple.finder")
        #expect(!decision.isAllowed)
    }

    @Test("third-party app on allowlist by team + signing ID is globally allowed")
    func thirdPartyGloballyAllowed() {
        let allowlist = [AllowlistEntry(signingID: "com.acme.backup", teamID: "ACME99")]
        let rules = [ruleProtecting("/protected")]
        let decision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/Applications/AcmeBackup", teamID: "ACME99", signingID: "com.acme.backup")
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("third-party app with wrong team ID falls through to policy")
    func thirdPartyWrongTeamHitsPolicy() {
        let allowlist = [AllowlistEntry(signingID: "com.acme.backup", teamID: "ACME99")]
        let rules = [ruleProtecting("/protected")]
        let decision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/anything", teamID: "EVIL77", signingID: "com.acme.backup")
        #expect(!decision.isAllowed)
        #expect(decision.matchedRuleID == ruleID)
    }

    // MARK: Global allowlist — path-based

    @Test("process on allowlist by path is globally allowed")
    func pathBasedGloballyAllowed() {
        let allowlist = [AllowlistEntry(processPath: "/usr/libexec/xprotect")]
        let rules = [ruleProtecting("/protected")]
        let decision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/usr/libexec/xprotect")
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("path-based allowlist entry rejects different path — falls through to policy")
    func pathMismatchHitsPolicy() {
        let allowlist = [AllowlistEntry(processPath: "/usr/libexec/xprotect")]
        let rules = [ruleProtecting("/protected")]
        let decision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/usr/bin/evil")
        #expect(!decision.isAllowed)
    }

    @Test("path-based allowlist does not prefix match")
    func pathAllowlistNoPrefixMatch() {
        let allowlist = [AllowlistEntry(processPath: "/usr/bin/tool")]
        let rules = [ruleProtecting("/protected")]
        let decision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/usr/bin/tool-extended")
        #expect(!decision.isAllowed)
    }

    @Test("path-based platform binary allowlist entry requires empty team")
    func pathPlatformBinaryEnforcesTeam() {
        let allowlist = [AllowlistEntry(processPath: "/Library/Apple/XProtect", platformBinary: true)]
        let rules = [ruleProtecting("/protected")]

        let allowed = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/Library/Apple/XProtect")
        guard case .globallyAllowed = allowed else {
            Issue.record("Expected .globallyAllowed, got \(allowed)")
            return
        }

        let denied = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/Library/Apple/XProtect", teamID: "TEAM")
        #expect(!denied.isAllowed)
    }

    // MARK: Global allowlist — mixed and multi-tier

    @Test("mixed allowlist — signing entry bypasses policy")
    func mixedAllowlistSigningBypasses() {
        let allowlist = [
            AllowlistEntry(signingID: "com.apple.mdworker", platformBinary: true),
            AllowlistEntry(processPath: "/usr/libexec/custom-scanner"),
        ]
        let rules = [ruleProtecting("/protected")]
        let decision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/System/mdworker", signingID: "com.apple.mdworker")
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("mixed allowlist — path entry bypasses policy when signing doesn't match")
    func mixedAllowlistPathBypasses() {
        let allowlist = [
            AllowlistEntry(signingID: "com.apple.mdworker", platformBinary: true),
            AllowlistEntry(processPath: "/usr/libexec/custom-scanner"),
        ]
        let rules = [ruleProtecting("/protected")]
        let decision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/usr/libexec/custom-scanner", teamID: "CUSTOM", signingID: "com.custom.scanner")
        guard case .globallyAllowed = decision else {
            Issue.record("Expected .globallyAllowed, got \(decision)")
            return
        }
    }

    @Test("mixed allowlist — neither entry matches, falls through to policy")
    func mixedAllowlistNeitherMatchesFallsThrough() {
        let allowlist = [
            AllowlistEntry(signingID: "com.apple.mdworker", platformBinary: true),
            AllowlistEntry(processPath: "/usr/libexec/custom-scanner"),
        ]
        let rules = [ruleProtecting("/protected")]
        let decision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/evil/binary", teamID: "EVIL", signingID: "com.evil")
        #expect(!decision.isAllowed)
    }

    @Test("multi-tier allowlist: baseline + managed + user entries")
    func multiTierAllowlist() {
        let baseline = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        let managed = [AllowlistEntry(signingID: "com.corp.agent", teamID: "CORP88")]
        let user = [AllowlistEntry(processPath: "/usr/local/bin/dev-tool")]
        let allowlist = baseline + managed + user
        let rules = [ruleProtecting("/protected")]

        let finderDecision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/System/Finder", signingID: "com.apple.finder")
        guard case .globallyAllowed = finderDecision else {
            Issue.record("Expected Finder to be globally allowed")
            return
        }

        let corpDecision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/opt/corp/agent", teamID: "CORP88", signingID: "com.corp.agent")
        guard case .globallyAllowed = corpDecision else {
            Issue.record("Expected corp agent to be globally allowed")
            return
        }

        let devToolDecision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/usr/local/bin/dev-tool")
        guard case .globallyAllowed = devToolDecision else {
            Issue.record("Expected dev-tool to be globally allowed")
            return
        }

        let unknownDecision = decide(rules: rules, allowlist: allowlist, path: "/protected/file", processPath: "/unknown", teamID: "UNK", signingID: "com.unknown")
        #expect(!unknownDecision.isAllowed)
    }

    // MARK: Global allowlist bypasses policy completely

    @Test("allowlisted process bypasses even a deny-all rule")
    func allowlistBypassesDenyAll() {
        let allowlist = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        let denyAllRule = FAARule(protectedPathPrefix: "/protected")
        let decision = decide(rules: [denyAllRule], allowlist: allowlist, path: "/protected/file", processPath: "/System/Finder", signingID: "com.apple.finder")
        guard case .globallyAllowed = decision else {
            Issue.record("Allowlisted process should bypass deny-all rule")
            return
        }
    }

    @Test("non-allowlisted process hitting unprotected path is noRuleApplies")
    func nonAllowlistedUnprotectedPath() {
        let allowlist = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        let rules = [ruleProtecting("/protected")]
        let decision = decide(rules: rules, allowlist: allowlist, path: "/unprotected/file", processPath: "/usr/bin/cat", teamID: "TEAM", signingID: "com.cat")
        guard case .noRuleApplies = decision else {
            Issue.record("Expected .noRuleApplies, got \(decision)")
            return
        }
    }

    // MARK: Policy evaluation — no rule applies

    @Test("unprotected path is allowed by default")
    func unprotectedPathAllowed() {
        let decision = decide(rules: [ruleProtecting("/protected")], path: "/unprotected/file", processPath: "/bin/cat")
        #expect(decision.isAllowed)
        #expect(decision.matchedRuleID == nil)
    }

    @Test("empty rules and empty allowlist allows everything")
    func emptyRulesAndAllowlistAllowsAll() {
        let decision = decide(path: "/anything", processPath: "/anything")
        guard case .noRuleApplies = decision else {
            Issue.record("Expected .noRuleApplies, got \(decision)")
            return
        }
    }

    // MARK: Policy evaluation — allowed by process path

    @Test("allowed by process path in rule")
    func allowedByProcessPath() {
        let rules = [ruleProtecting("/protected", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = decide(rules: rules, path: "/protected/file", processPath: "/usr/bin/safe")
        #expect(decision.isAllowed)
    }

    @Test("denied when process path not in rule's allowed list")
    func deniedWhenProcessPathNotAllowed() {
        let rules = [ruleProtecting("/protected", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = decide(rules: rules, path: "/protected/file", processPath: "/usr/bin/evil")
        #expect(!decision.isAllowed)
        #expect(decision.matchedRuleID == ruleID)
    }

    // MARK: Policy evaluation — allowed by signature

    @Test("allowed by exact signature")
    func allowedByExactSignature() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = decide(rules: rules, path: "/protected/file", processPath: "/anything", teamID: "TEAM1", signingID: "com.example.app")
        #expect(decision.isAllowed)
    }

    @Test("allowed by wildcard signature")
    func allowedByWildcardSignature() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "*")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = decide(rules: rules, path: "/protected/file", processPath: "/anything", teamID: "TEAM1", signingID: "com.anything")
        #expect(decision.isAllowed)
    }

    @Test("Apple platform binary gets resolved team ID in policy")
    func applePlatformBinaryResolution() {
        let sig = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.finder")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = decide(rules: rules, path: "/protected/file", processPath: "/System/Finder", signingID: "com.apple.finder")
        #expect(decision.isAllowed)
    }

    @Test("denied when signature does not match")
    func deniedWhenSignatureMismatch() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = decide(rules: rules, path: "/protected/file", processPath: "/anything", teamID: "TEAM2", signingID: "com.evil")
        #expect(!decision.isAllowed)
    }

    // MARK: Policy evaluation — allowed by ancestor

    @Test("allowed by ancestor process path")
    func allowedByAncestorProcessPath() {
        let rules = [ruleProtecting("/protected", allowedAncestorProcessPaths: ["/usr/bin/parent"])]
        let ancestors = [AncestorInfo(path: "/usr/bin/parent", teamID: "", signingID: "")]
        let decision = decide(rules: rules, path: "/protected/file", processPath: "/usr/bin/child", ancestors: ancestors)
        #expect(decision.isAllowed)
    }

    @Test("allowed by ancestor signature")
    func allowedByAncestorSignature() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "*")
        let rules = [ruleProtecting("/protected", allowedAncestorSignatures: [sig])]
        let ancestors = [AncestorInfo(path: "/some/parent", teamID: "TEAM1", signingID: "com.parent")]
        let decision = decide(rules: rules, path: "/protected/file", processPath: "/child", ancestors: ancestors)
        #expect(decision.isAllowed)
    }

    @Test("ancestor with empty team ID resolved to apple")
    func ancestorAppleResolution() {
        let sig = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.launchd")
        let rules = [ruleProtecting("/protected", allowedAncestorSignatures: [sig])]
        let ancestors = [AncestorInfo(path: "/sbin/launchd", teamID: "", signingID: "com.apple.launchd")]
        let decision = decide(rules: rules, path: "/protected/file", processPath: "/child", teamID: "SOMETEAM", signingID: "com.child", ancestors: ancestors)
        #expect(decision.isAllowed)
    }

    @Test("denied when no ancestor matches")
    func deniedWhenNoAncestorMatches() {
        let rules = [ruleProtecting("/protected", allowedAncestorProcessPaths: ["/usr/bin/parent"])]
        let ancestors = [AncestorInfo(path: "/usr/bin/other", teamID: "", signingID: "")]
        let decision = decide(rules: rules, path: "/protected/file", processPath: "/child", ancestors: ancestors)
        #expect(!decision.isAllowed)
    }

    // MARK: Policy evaluation — first match wins

    @Test("first matching rule wins — earlier allow beats later deny")
    func firstRuleWins() {
        let allowRule = FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/usr/bin/safe"])
        let denyAllRule = FAARule(protectedPathPrefix: "/protected")
        let decision = decide(rules: [allowRule, denyAllRule], path: "/protected/file", processPath: "/usr/bin/safe")
        #expect(decision.isAllowed)
    }

    @Test("first matching rule wins — earlier deny beats later allow")
    func firstDenyWins() {
        let denyAllRule = FAARule(protectedPathPrefix: "/protected")
        let allowRule = FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/usr/bin/safe"])
        let decision = decide(rules: [denyAllRule, allowRule], path: "/protected/file", processPath: "/usr/bin/safe")
        #expect(!decision.isAllowed)
    }

    // MARK: Policy evaluation — deny reason

    @Test("deny reason includes rule and criteria")
    func denyReasonContent() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "com.allowed")
        let rules = [ruleProtecting("/secret", allowedSignatures: [sig])]
        let decision = decide(rules: rules, path: "/secret/file", processPath: "/evil", teamID: "BAD", signingID: "com.evil")
        #expect(decision.reason.contains("/secret"))
        #expect(decision.reason.contains("TEAM1:com.allowed"))
    }

    // MARK: Policy evaluation — wildcard path rules

    @Test("wildcard rule protects matching paths")
    func wildcardRuleProtectsMatchingPaths() {
        let rules = [ruleProtecting("/Users/*/Documents", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = decide(rules: rules, path: "/Users/admin/Documents/secret.txt", processPath: "/usr/bin/evil")
        #expect(!decision.isAllowed)
    }

    @Test("wildcard rule allows matching process")
    func wildcardRuleAllowsMatchingProcess() {
        let rules = [ruleProtecting("/Users/*/Documents", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = decide(rules: rules, path: "/Users/admin/Documents/secret.txt", processPath: "/usr/bin/safe")
        #expect(decision.isAllowed)
    }

    @Test("wildcard rule does not apply to non-matching paths")
    func wildcardRuleIgnoresNonMatchingPaths() {
        let rules = [ruleProtecting("/Users/*/Documents", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = decide(rules: rules, path: "/Users/admin/Downloads/file.txt", processPath: "/usr/bin/evil")
        #expect(decision.isAllowed)
    }

    // MARK: Policy evaluation — multiple criteria

    @Test("process path checked before signature")
    func processPathCheckedFirst() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "*")
        let rules = [ruleProtecting("/protected", allowedProcessPaths: ["/usr/bin/safe"], allowedSignatures: [sig])]
        let decision = decide(rules: rules, path: "/protected/file", processPath: "/usr/bin/safe", teamID: "TEAM1", signingID: "com.x")
        #expect(decision.isAllowed)
        #expect(decision.reason.contains("process path"))
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
