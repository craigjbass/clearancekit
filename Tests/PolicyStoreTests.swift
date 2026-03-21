//
//  PolicyStoreTests.swift
//  clearancekitTests
//

import Testing
import Foundation

// MARK: - Helpers

private func makeRule(path: String = "/protected/path") -> FAARule {
    FAARule(protectedPathPrefix: path)
}

// MARK: - PolicyStoreTests

@Suite("PolicyStore")
@MainActor
struct PolicyStoreTests {

    // MARK: add

    @Test("add appends rule to userRules and forwards to service")
    func addAppendsRuleAndForwardsToService() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rule = makeRule()

        try await store.add(rule)

        #expect(store.userRules == [rule])
        #expect(service.addedRules == [rule])
    }

    @Test("add does nothing when authentication fails")
    func addDoesNothingOnAuthFailure() async {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: failingAuth)
        let rule = makeRule()

        do {
            try await store.add(rule)
            Issue.record("Expected authentication error")
        } catch {}

        #expect(store.userRules.isEmpty)
        #expect(service.addedRules.isEmpty)
    }

    // MARK: update

    @Test("update replaces existing rule and forwards to service")
    func updateReplacesRuleAndForwards() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rule = makeRule()
        store.receivedUserRules([rule])
        let updated = FAARule(id: rule.id, protectedPathPrefix: "/updated/path")

        try await store.update(updated)

        #expect(store.userRules == [updated])
        #expect(service.updatedRules == [updated])
    }

    @Test("update ignores rule not in userRules")
    func updateIgnoresUnknownRule() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)

        try await store.update(makeRule())

        #expect(store.userRules.isEmpty)
        #expect(service.updatedRules.isEmpty)
    }

    // MARK: remove

    @Test("remove deletes rule from userRules and forwards ID to service")
    func removeDeletesRuleAndForwards() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rule = makeRule()
        store.receivedUserRules([rule])

        try await store.remove(rule)

        #expect(store.userRules.isEmpty)
        #expect(service.removedRuleIDs == [rule.id])
    }

    // MARK: allowProcess

    @Test("allowProcess adds signature to matching rule and forwards update")
    func allowProcessAddsSignatureAndForwards() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rule = makeRule()
        store.receivedUserRules([rule])

        try await store.allowProcess(teamID: "TEAM1", signingID: "com.example.app", inRule: rule.id)

        let expectedSig = ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")
        #expect(store.userRules.first?.allowedSignatures == [expectedSig])
        #expect(service.updatedRules.count == 1)
    }

    @Test("allowProcess uses appleTeamID when teamID is empty")
    func allowProcessUsesAppleTeamIDForEmptyTeamID() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rule = makeRule()
        store.receivedUserRules([rule])

        try await store.allowProcess(teamID: "", signingID: "com.apple.thing", inRule: rule.id)

        let expectedSig = ProcessSignature(teamID: appleTeamID, signingID: "com.apple.thing")
        #expect(store.userRules.first?.allowedSignatures == [expectedSig])
    }

    @Test("allowProcess uses wildcard signingID when signingID is empty")
    func allowProcessUsesWildcardSigningIDWhenEmpty() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rule = makeRule()
        store.receivedUserRules([rule])

        try await store.allowProcess(teamID: "TEAM1", signingID: "", inRule: rule.id)

        let expectedSig = ProcessSignature(teamID: "TEAM1", signingID: "*")
        #expect(store.userRules.first?.allowedSignatures == [expectedSig])
    }

    @Test("allowProcess does not add duplicate signatures")
    func allowProcessDoesNotAddDuplicateSignatures() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let sig = ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")
        let rule = FAARule(protectedPathPrefix: "/protected", allowedSignatures: [sig])
        store.receivedUserRules([rule])

        try await store.allowProcess(teamID: "TEAM1", signingID: "com.example.app", inRule: rule.id)

        #expect(store.userRules.first?.allowedSignatures.count == 1)
    }

    // MARK: addAll

    @Test("addAll appends new rules and forwards each to service")
    func addAllAppendsNewRulesAndForwards() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rules = [makeRule(path: "/a"), makeRule(path: "/b")]

        try await store.addAll(rules, reason: "import")

        #expect(store.userRules.count == 2)
        #expect(service.addedRules.count == 2)
    }

    @Test("addAll skips rules already in userRules")
    func addAllSkipsDuplicates() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let existing = makeRule(path: "/existing")
        store.receivedUserRules([existing])

        try await store.addAll([existing, makeRule(path: "/new")], reason: "import")

        #expect(store.userRules.count == 2)
        #expect(service.addedRules.count == 1)
    }

    @Test("addAll does nothing when all rules are already present")
    func addAllDoesNothingWhenAllPresent() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rule = makeRule()
        store.receivedUserRules([rule])

        try await store.addAll([rule], reason: "import")

        #expect(store.userRules.count == 1)
        #expect(service.addedRules.isEmpty)
    }

    // MARK: removeAll

    @Test("removeAll removes matching rules and forwards each ID to service")
    func removeAllRemovesAndForwards() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rules = [makeRule(path: "/a"), makeRule(path: "/b")]
        store.receivedUserRules(rules)

        try await store.removeAll(rules, reason: "clear")

        #expect(store.userRules.isEmpty)
        #expect(service.removedRuleIDs.count == 2)
    }

    @Test("removeAll does nothing when none of the rules are present")
    func removeAllDoesNothingWhenNonePresent() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)

        try await store.removeAll([makeRule()], reason: "clear")

        #expect(service.removedRuleIDs.isEmpty)
    }

    // MARK: updateAll

    @Test("updateAll replaces matching rules and forwards each to service")
    func updateAllReplacesAndForwards() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rule = makeRule()
        store.receivedUserRules([rule])
        let updated = FAARule(id: rule.id, protectedPathPrefix: "/updated")

        try await store.updateAll([updated], reason: "update")

        #expect(store.userRules == [updated])
        #expect(service.updatedRules == [updated])
    }

    @Test("updateAll does nothing when none of the rules are present")
    func updateAllDoesNothingWhenNonePresent() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)

        try await store.updateAll([makeRule()], reason: "update")

        #expect(service.updatedRules.isEmpty)
    }

    // MARK: replaceAll

    @Test("replaceAll removes old rules and adds new ones")
    func replaceAllSwapsRules() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let old = makeRule(path: "/old")
        store.receivedUserRules([old])
        let new = makeRule(path: "/new")

        try await store.replaceAll([old], with: [new], reason: "replace")

        #expect(store.userRules == [new])
        #expect(service.removedRuleIDs == [old.id])
        #expect(service.addedRules == [new])
    }

    // MARK: allowAncestor

    @Test("allowAncestor adds ancestor signature to matching rule and forwards update")
    func allowAncestorAddsSignatureAndForwards() async throws {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rule = makeRule()
        store.receivedUserRules([rule])

        try await store.allowAncestor(teamID: "TEAM1", signingID: "com.example.launcher", inRule: rule.id)

        let expectedSig = ProcessSignature(teamID: "TEAM1", signingID: "com.example.launcher")
        #expect(store.userRules.first?.allowedAncestorSignatures == [expectedSig])
        #expect(service.updatedRules.count == 1)
    }

    // MARK: receivedManagedRules / receivedUserRules

    @Test("receivedManagedRules updates managedRules")
    func receivedManagedRulesUpdates() {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rules = [makeRule()]

        store.receivedManagedRules(rules)

        #expect(store.managedRules == rules)
    }

    @Test("receivedUserRules updates userRules")
    func receivedUserRulesUpdates() {
        let service = FakePolicyService()
        let store = PolicyStore(service: service, authenticate: approvedAuth)
        let rules = [makeRule()]

        store.receivedUserRules(rules)

        #expect(store.userRules == rules)
    }
}
