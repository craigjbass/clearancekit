//
//  JailStoreTests.swift
//  clearancekitTests
//

import Testing
import Foundation

// MARK: - Helpers

private func makeJailRule(name: String = "Test Jail") -> JailRule {
    JailRule(
        name: name,
        jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.app"),
        allowedPathPrefixes: ["/tmp"]
    )
}

// MARK: - JailStoreTests

@Suite("JailStore")
@MainActor
struct JailStoreTests {

    // MARK: - isEnabled

    @Test("isEnabled defaults to false")
    func isEnabledDefaultsFalse() {
        let service = FakePolicyService()
        let store = JailStore(service: service, authenticate: approvedAuth)

        #expect(store.isEnabled == false)
    }

    @Test("receivedJailEnabled updates isEnabled")
    func receivedJailEnabledUpdatesState() {
        let service = FakePolicyService()
        let store = JailStore(service: service, authenticate: approvedAuth)

        store.receivedJailEnabled(true)

        #expect(store.isEnabled == true)
    }

    @Test("setEnabled updates local state and forwards to service")
    func setEnabledUpdatesAndForwards() {
        let service = FakePolicyService()
        let store = JailStore(service: service, authenticate: approvedAuth)

        store.setEnabled(true)

        #expect(store.isEnabled == true)
        #expect(service.jailEnabledCalls == [true])
    }

    @Test("setEnabled to false disables and forwards to service")
    func setEnabledFalseDisablesAndForwards() {
        let service = FakePolicyService()
        let store = JailStore(service: service, authenticate: approvedAuth)
        store.receivedJailEnabled(true)

        store.setEnabled(false)

        #expect(store.isEnabled == false)
        #expect(service.jailEnabledCalls == [false])
    }

    // MARK: - Existing behaviour

    @Test("add appends rule and forwards to service")
    func addAppendsRuleAndForwards() async throws {
        let service = FakePolicyService()
        let store = JailStore(service: service, authenticate: approvedAuth)
        let rule = makeJailRule()

        try await store.add(rule)

        #expect(store.userRules == [rule])
        #expect(service.addedJailRules == [rule])
    }

    @Test("remove deletes rule and forwards to service")
    func removeDeletesRuleAndForwards() async throws {
        let service = FakePolicyService()
        let store = JailStore(service: service, authenticate: approvedAuth)
        let rule = makeJailRule()
        store.receivedUserRules([rule])

        try await store.remove(rule)

        #expect(store.userRules.isEmpty)
        #expect(service.removedJailRuleIDs == [rule.id])
    }
}
