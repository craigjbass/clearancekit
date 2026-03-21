//
//  JailRuleTests.swift
//  clearancekitTests
//

import Testing
import Foundation

// MARK: - checkJailPolicy

@Suite("checkJailPolicy")
struct JailPolicyTests {

    private let jailRule = JailRule(
        name: "Confine Example App",
        jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.app"),
        allowedPathPrefixes: ["/Users/admin/Documents/Example/**", "/tmp"]
    )

    @Test("returns noRuleApplies when jail rules list is empty")
    func emptyJailRules() {
        let decision = checkJailPolicy(jailRules: [], path: "/any/path", teamID: "TEAM1", signingID: "com.example.app")
        #expect(decision.jailedRuleID == nil)
        #expect(decision.isAllowed)
    }

    @Test("returns noRuleApplies when process does not match any jail rule")
    func nonMatchingProcess() {
        let decision = checkJailPolicy(jailRules: [jailRule], path: "/any/path", teamID: "OTHER", signingID: "com.other.app")
        #expect(decision.jailedRuleID == nil)
        #expect(decision.isAllowed)
    }

    @Test("/** allows access to files at any depth below base")
    func doubleStarAllowsAnyDepth() {
        let decision = checkJailPolicy(jailRules: [jailRule], path: "/Users/admin/Documents/Example/file.txt", teamID: "TEAM1", signingID: "com.example.app")
        guard case .jailAllowed(let ruleID, _, let prefix) = decision else {
            Issue.record("Expected jailAllowed, got \(decision)")
            return
        }
        #expect(ruleID == jailRule.id)
        #expect(prefix == "/Users/admin/Documents/Example/**")
    }

    @Test("exact pattern allows access to the exact path only")
    func exactPatternAllowsExactPath() {
        let decision = checkJailPolicy(jailRules: [jailRule], path: "/tmp", teamID: "TEAM1", signingID: "com.example.app")
        guard case .jailAllowed(_, _, let prefix) = decision else {
            Issue.record("Expected jailAllowed, got \(decision)")
            return
        }
        #expect(prefix == "/tmp")
    }

    @Test("exact pattern denies access to paths below it")
    func exactPatternDeniesPathsBelow() {
        let decision = checkJailPolicy(jailRules: [jailRule], path: "/tmp/foo", teamID: "TEAM1", signingID: "com.example.app")
        guard case .jailDenied = decision else {
            Issue.record("Expected jailDenied, got \(decision)")
            return
        }
    }

    @Test("/* allows exactly one level of nesting")
    func singleStarAllowsOneLevel() {
        let rule = JailRule(
            name: "One Level",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.app"),
            allowedPathPrefixes: ["/usr/*"]
        )
        let allowed = checkJailPolicy(jailRules: [rule], path: "/usr/bin", teamID: "TEAM1", signingID: "com.example.app")
        guard case .jailAllowed = allowed else {
            Issue.record("Expected jailAllowed for /usr/bin, got \(allowed)")
            return
        }
        let denied = checkJailPolicy(jailRules: [rule], path: "/usr/bin/node", teamID: "TEAM1", signingID: "com.example.app")
        guard case .jailDenied = denied else {
            Issue.record("Expected jailDenied for /usr/bin/node, got \(denied)")
            return
        }
    }

    @Test("/** also allows access to the base directory itself")
    func doubleStarAllowsBase() {
        let rule = JailRule(
            name: "Full Access",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.app"),
            allowedPathPrefixes: ["/usr/**"]
        )
        let decision = checkJailPolicy(jailRules: [rule], path: "/usr", teamID: "TEAM1", signingID: "com.example.app")
        guard case .jailAllowed = decision else {
            Issue.record("Expected jailAllowed for /usr, got \(decision)")
            return
        }
    }

    @Test("denies access when path is outside all allowed prefixes")
    func deniedPath() {
        let decision = checkJailPolicy(jailRules: [jailRule], path: "/etc/passwd", teamID: "TEAM1", signingID: "com.example.app")
        guard case .jailDenied(let ruleID, _, let prefixes) = decision else {
            Issue.record("Expected jailDenied, got \(decision)")
            return
        }
        #expect(ruleID == jailRule.id)
        #expect(prefixes == jailRule.allowedPathPrefixes)
    }

    @Test("rejects path that shares a prefix but not at a component boundary")
    func partialComponentBoundary() {
        let decision = checkJailPolicy(jailRules: [jailRule], path: "/Users/admin/Documents/ExampleExtra/file.txt", teamID: "TEAM1", signingID: "com.example.app")
        guard case .jailDenied = decision else {
            Issue.record("Expected jailDenied, got \(decision)")
            return
        }
    }

    @Test("resolves empty team ID to apple team ID for matching")
    func appleTeamIDResolution() {
        let appleJail = JailRule(
            name: "Jail Apple Tool",
            jailedSignature: ProcessSignature(teamID: appleTeamID, signingID: "com.apple.tool"),
            allowedPathPrefixes: ["/usr/local/**"]
        )
        let decision = checkJailPolicy(jailRules: [appleJail], path: "/usr/local/bin/thing", teamID: "", signingID: "com.apple.tool")
        guard case .jailAllowed = decision else {
            Issue.record("Expected jailAllowed, got \(decision)")
            return
        }
    }

    @Test("wildcard signingID in jail rule matches any signing ID for that team")
    func wildcardSigningID() {
        let wildcardJail = JailRule(
            name: "Jail All Team Apps",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "*"),
            allowedPathPrefixes: ["/allowed"]
        )
        let decision = checkJailPolicy(jailRules: [wildcardJail], path: "/forbidden/file", teamID: "TEAM1", signingID: "com.any.app")
        guard case .jailDenied = decision else {
            Issue.record("Expected jailDenied, got \(decision)")
            return
        }
    }

    @Test("jail decision reason includes rule name")
    func decisionReasonIncludesRuleName() {
        let decision = checkJailPolicy(jailRules: [jailRule], path: "/etc/passwd", teamID: "TEAM1", signingID: "com.example.app")
        #expect(decision.reason.contains("Confine Example App"))
    }
}

// MARK: - PolicyDecision jail properties

@Suite("PolicyDecision jail cases")
struct PolicyDecisionJailTests {

    @Test("jailAllowed is allowed")
    func jailAllowedIsAllowed() {
        let decision = PolicyDecision.jailAllowed(ruleID: UUID(), ruleName: "Test", matchedPrefix: "/path")
        #expect(decision.isAllowed)
    }

    @Test("jailDenied is not allowed")
    func jailDeniedIsNotAllowed() {
        let decision = PolicyDecision.jailDenied(ruleID: UUID(), ruleName: "Test", allowedPrefixes: [])
        #expect(!decision.isAllowed)
    }

    @Test("jailAllowed has jailedRuleID")
    func jailAllowedHasJailedRuleID() {
        let id = UUID()
        let decision = PolicyDecision.jailAllowed(ruleID: id, ruleName: "Test", matchedPrefix: "/path")
        #expect(decision.jailedRuleID == id)
        #expect(decision.matchedRuleID == id)
    }

    @Test("jailDenied has jailedRuleID")
    func jailDeniedHasJailedRuleID() {
        let id = UUID()
        let decision = PolicyDecision.jailDenied(ruleID: id, ruleName: "Test", allowedPrefixes: [])
        #expect(decision.jailedRuleID == id)
        #expect(decision.matchedRuleID == id)
    }

    @Test("non-jail decisions have nil jailedRuleID")
    func nonJailDecisionsHaveNilJailedRuleID() {
        #expect(PolicyDecision.globallyAllowed.jailedRuleID == nil)
        #expect(PolicyDecision.noRuleApplies.jailedRuleID == nil)
    }

    @Test("jail policyName returns rule name")
    func jailPolicyName() {
        let decision = PolicyDecision.jailDenied(ruleID: UUID(), ruleName: "MyJail", allowedPrefixes: [])
        #expect(decision.policyName == "MyJail")
    }
}

// MARK: - checkJailPath

@Suite("checkJailPath")
struct CheckJailPathTests {

    private let rule = JailRule(
        name: "Path Rule",
        jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.app"),
        allowedPathPrefixes: ["/allowed/**", "/exact"]
    )

    @Test("allows path matching /** pattern")
    func allowsDoubleStarPath() {
        let decision = checkJailPath(rule: rule, path: "/allowed/data.db")
        #expect(decision.isAllowed)
        #expect(decision.jailedRuleID == rule.id)
    }

    @Test("allows base directory matched by /**")
    func allowsBaseDirectory() {
        let decision = checkJailPath(rule: rule, path: "/allowed")
        #expect(decision.isAllowed)
    }

    @Test("allows exact path match")
    func allowsExactPath() {
        let decision = checkJailPath(rule: rule, path: "/exact")
        #expect(decision.isAllowed)
    }

    @Test("denies path not in allowed list")
    func deniesUnallowedPath() {
        let decision = checkJailPath(rule: rule, path: "/forbidden/file")
        #expect(!decision.isAllowed)
        #expect(decision.jailedRuleID == rule.id)
    }

    @Test("does not match signing ID — evaluates any process against the rule")
    func ignoresSigningID() {
        // checkJailPath is used for inherited jails where the child's signing ID
        // does not match the rule's jailedSignature.
        let decision = checkJailPath(rule: rule, path: "/exact")
        guard case .jailAllowed = decision else {
            Issue.record("Expected jailAllowed, got \(decision)")
            return
        }
    }
}

// MARK: - JailRule Codable

@Suite("JailRule Codable")
struct JailRuleCodableTests {

    @Test("round-trips through JSON encoding and decoding")
    func codableRoundTrip() throws {
        let original = JailRule(
            name: "Test Rule",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.app"),
            allowedPathPrefixes: ["/Users/admin", "/tmp"]
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(JailRule.self, from: data)

        #expect(decoded.id == original.id)
        #expect(decoded.name == original.name)
        #expect(decoded.source == original.source)
        #expect(decoded.jailedSignature == original.jailedSignature)
        #expect(decoded.allowedPathPrefixes == original.allowedPathPrefixes)
    }
}
