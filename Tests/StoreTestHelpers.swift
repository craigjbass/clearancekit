//
//  StoreTestHelpers.swift
//  clearancekitTests
//

import Foundation

// MARK: - FakePolicyService

@MainActor
final class FakePolicyService: PolicyServiceProtocol {
    private(set) var addedRules: [FAARule] = []
    private(set) var updatedRules: [FAARule] = []
    private(set) var removedRuleIDs: [UUID] = []
    private(set) var addedEntries: [AllowlistEntry] = []
    private(set) var removedEntryIDs: [UUID] = []
    private(set) var addedAncestorEntries: [AncestorAllowlistEntry] = []
    private(set) var removedAncestorEntryIDs: [UUID] = []
    private(set) var addedJailRules: [JailRule] = []
    private(set) var updatedJailRules: [JailRule] = []
    private(set) var removedJailRuleIDs: [UUID] = []
    private(set) var jailEnabledCalls: [Bool] = []

    func addRule(_ rule: FAARule) { addedRules.append(rule) }
    func updateRule(_ rule: FAARule) { updatedRules.append(rule) }
    func removeRule(ruleID: UUID) { removedRuleIDs.append(ruleID) }
    func addAllowlistEntry(_ entry: AllowlistEntry) { addedEntries.append(entry) }
    func removeAllowlistEntry(entryID: UUID) { removedEntryIDs.append(entryID) }
    func addAncestorAllowlistEntry(_ entry: AncestorAllowlistEntry) { addedAncestorEntries.append(entry) }
    func removeAncestorAllowlistEntry(entryID: UUID) { removedAncestorEntryIDs.append(entryID) }
    func addJailRule(_ rule: JailRule) { addedJailRules.append(rule) }
    func updateJailRule(_ rule: JailRule) { updatedJailRules.append(rule) }
    func removeJailRule(ruleID: UUID) { removedJailRuleIDs.append(ruleID) }
    func setJailEnabled(_ enabled: Bool) { jailEnabledCalls.append(enabled) }
    func saveBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature]) {}
}

// MARK: - Auth helpers

struct AuthError: Error {}

let approvedAuth: Authenticate = { _ in }
let failingAuth: Authenticate = { _ in throw AuthError() }
