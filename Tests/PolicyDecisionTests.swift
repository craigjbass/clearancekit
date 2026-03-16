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

// MARK: - isGloballyAllowed

@Suite("isGloballyAllowed")
struct GlobalAllowlistTests {
    @Test("allowed process passes")
    func allowedProcessPasses() {
        let allowlist = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        #expect(isGloballyAllowed(allowlist: allowlist, processPath: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", signingID: "com.apple.finder", teamID: ""))
    }

    @Test("unknown process rejected")
    func unknownProcessRejected() {
        let allowlist = [AllowlistEntry(signingID: "com.apple.finder", platformBinary: true)]
        #expect(!isGloballyAllowed(allowlist: allowlist, processPath: "/evil", signingID: "com.evil.app", teamID: "EVIL"))
    }

    @Test("empty allowlist rejects everything")
    func emptyAllowlistRejectsAll() {
        #expect(!isGloballyAllowed(allowlist: [], processPath: "/anything", signingID: "anything", teamID: ""))
    }
}

// MARK: - checkFAAPolicy

@Suite("checkFAAPolicy")
struct PolicyEvaluationTests {
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

    // MARK: No rule applies

    @Test("unprotected path is allowed by default")
    func unprotectedPathAllowed() {
        let rules = [ruleProtecting("/protected")]
        let decision = checkFAAPolicy(rules: rules, path: "/unprotected/file", processPath: "/bin/cat", teamID: "", signingID: "")
        #expect(decision.isAllowed)
        #expect(decision.matchedRuleID == nil)
    }

    @Test("empty rule set allows everything")
    func emptyRuleSetAllowsAll() {
        let decision = checkFAAPolicy(rules: [], path: "/anything", processPath: "/anything", teamID: "", signingID: "")
        #expect(decision.isAllowed)
    }

    // MARK: Allowed by process path

    @Test("allowed by process path")
    func allowedByProcessPath() {
        let rules = [ruleProtecting("/protected", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = checkFAAPolicy(rules: rules, path: "/protected/file", processPath: "/usr/bin/safe", teamID: "", signingID: "")
        #expect(decision.isAllowed)
    }

    @Test("denied when process path not in allowed list")
    func deniedWhenProcessPathNotAllowed() {
        let rules = [ruleProtecting("/protected", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = checkFAAPolicy(rules: rules, path: "/protected/file", processPath: "/usr/bin/evil", teamID: "", signingID: "")
        #expect(!decision.isAllowed)
        #expect(decision.matchedRuleID == ruleID)
    }

    // MARK: Allowed by signature

    @Test("allowed by exact signature")
    func allowedByExactSignature() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = checkFAAPolicy(rules: rules, path: "/protected/file", processPath: "/anything", teamID: "TEAM1", signingID: "com.example.app")
        #expect(decision.isAllowed)
    }

    @Test("allowed by wildcard signature")
    func allowedByWildcardSignature() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "*")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = checkFAAPolicy(rules: rules, path: "/protected/file", processPath: "/anything", teamID: "TEAM1", signingID: "com.anything")
        #expect(decision.isAllowed)
    }

    @Test("Apple platform binary gets resolved team ID")
    func applePlatformBinaryResolution() {
        let sig = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.finder")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        // Empty teamID → resolved to appleTeamID
        let decision = checkFAAPolicy(rules: rules, path: "/protected/file", processPath: "/System/Finder", teamID: "", signingID: "com.apple.finder")
        #expect(decision.isAllowed)
    }

    @Test("denied when signature does not match")
    func deniedWhenSignatureMismatch() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")
        let rules = [ruleProtecting("/protected", allowedSignatures: [sig])]
        let decision = checkFAAPolicy(rules: rules, path: "/protected/file", processPath: "/anything", teamID: "TEAM2", signingID: "com.evil")
        #expect(!decision.isAllowed)
    }

    // MARK: Allowed by ancestor

    @Test("allowed by ancestor process path")
    func allowedByAncestorProcessPath() {
        let rules = [ruleProtecting("/protected", allowedAncestorProcessPaths: ["/usr/bin/parent"])]
        let ancestors = [AncestorInfo(path: "/usr/bin/parent", teamID: "", signingID: "")]
        let decision = checkFAAPolicy(rules: rules, path: "/protected/file", processPath: "/usr/bin/child", teamID: "", signingID: "", ancestors: ancestors)
        #expect(decision.isAllowed)
    }

    @Test("allowed by ancestor signature")
    func allowedByAncestorSignature() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "*")
        let rules = [ruleProtecting("/protected", allowedAncestorSignatures: [sig])]
        let ancestors = [AncestorInfo(path: "/some/parent", teamID: "TEAM1", signingID: "com.parent")]
        let decision = checkFAAPolicy(rules: rules, path: "/protected/file", processPath: "/child", teamID: "", signingID: "", ancestors: ancestors)
        #expect(decision.isAllowed)
    }

    @Test("ancestor with empty team ID resolved to apple")
    func ancestorAppleResolution() {
        let sig = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.launchd")
        let rules = [ruleProtecting("/protected", allowedAncestorSignatures: [sig])]
        let ancestors = [AncestorInfo(path: "/sbin/launchd", teamID: "", signingID: "com.apple.launchd")]
        let decision = checkFAAPolicy(rules: rules, path: "/protected/file", processPath: "/child", teamID: "SOMETEAM", signingID: "com.child", ancestors: ancestors)
        #expect(decision.isAllowed)
    }

    @Test("denied when no ancestor matches")
    func deniedWhenNoAncestorMatches() {
        let rules = [ruleProtecting("/protected", allowedAncestorProcessPaths: ["/usr/bin/parent"])]
        let ancestors = [AncestorInfo(path: "/usr/bin/other", teamID: "", signingID: "")]
        let decision = checkFAAPolicy(rules: rules, path: "/protected/file", processPath: "/child", teamID: "", signingID: "", ancestors: ancestors)
        #expect(!decision.isAllowed)
    }

    // MARK: First match wins

    @Test("first matching rule wins — earlier allow beats later deny")
    func firstRuleWins() {
        let allowRule = FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/usr/bin/safe"])
        let denyAllRule = FAARule(protectedPathPrefix: "/protected")
        let decision = checkFAAPolicy(rules: [allowRule, denyAllRule], path: "/protected/file", processPath: "/usr/bin/safe", teamID: "", signingID: "")
        #expect(decision.isAllowed)
    }

    @Test("first matching rule wins — earlier deny beats later allow")
    func firstDenyWins() {
        let denyAllRule = FAARule(protectedPathPrefix: "/protected")
        let allowRule = FAARule(protectedPathPrefix: "/protected", allowedProcessPaths: ["/usr/bin/safe"])
        let decision = checkFAAPolicy(rules: [denyAllRule, allowRule], path: "/protected/file", processPath: "/usr/bin/safe", teamID: "", signingID: "")
        #expect(!decision.isAllowed)
    }

    // MARK: Deny reason

    @Test("deny reason includes rule and criteria")
    func denyReasonContent() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "com.allowed")
        let rules = [ruleProtecting("/secret", allowedSignatures: [sig])]
        let decision = checkFAAPolicy(rules: rules, path: "/secret/file", processPath: "/evil", teamID: "BAD", signingID: "com.evil")
        #expect(decision.reason.contains("/secret"))
        #expect(decision.reason.contains("TEAM1:com.allowed"))
    }

    // MARK: Wildcard path rules

    @Test("wildcard rule protects matching paths")
    func wildcardRuleProtectsMatchingPaths() {
        let rules = [ruleProtecting("/Users/*/Documents", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = checkFAAPolicy(rules: rules, path: "/Users/admin/Documents/secret.txt", processPath: "/usr/bin/evil", teamID: "", signingID: "")
        #expect(!decision.isAllowed)
    }

    @Test("wildcard rule allows matching process")
    func wildcardRuleAllowsMatchingProcess() {
        let rules = [ruleProtecting("/Users/*/Documents", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = checkFAAPolicy(rules: rules, path: "/Users/admin/Documents/secret.txt", processPath: "/usr/bin/safe", teamID: "", signingID: "")
        #expect(decision.isAllowed)
    }

    @Test("wildcard rule does not apply to non-matching paths")
    func wildcardRuleIgnoresNonMatchingPaths() {
        let rules = [ruleProtecting("/Users/*/Documents", allowedProcessPaths: ["/usr/bin/safe"])]
        let decision = checkFAAPolicy(rules: rules, path: "/Users/admin/Downloads/file.txt", processPath: "/usr/bin/evil", teamID: "", signingID: "")
        #expect(decision.isAllowed) // no rule applies
    }

    // MARK: Multiple criteria

    @Test("process path checked before signature")
    func processPathCheckedFirst() {
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "*")
        let rules = [ruleProtecting("/protected", allowedProcessPaths: ["/usr/bin/safe"], allowedSignatures: [sig])]
        // Process matches by path — should report process path as the matched criterion
        let decision = checkFAAPolicy(rules: rules, path: "/protected/file", processPath: "/usr/bin/safe", teamID: "TEAM1", signingID: "com.x")
        #expect(decision.isAllowed)
        #expect(decision.reason.contains("process path"))
    }
}
