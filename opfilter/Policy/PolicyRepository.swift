//
//  PolicyRepository.swift
//  opfilter
//
//  Owns policy and allowlist state, persistence, and signature-issue handling.
//  XPCServer wires this to the filter and to EventBroadcaster.
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "policy-repository")

// MARK: - DatabaseLoadResult

enum DatabaseLoadResult<T> {
    case ok([T])
    case suspect([T])
}

// MARK: - PolicyDatabaseProtocol

protocol PolicyDatabaseProtocol: AnyObject {
    func loadUserRulesResult() -> DatabaseLoadResult<FAARule>
    func loadUserAllowlistResult() -> DatabaseLoadResult<AllowlistEntry>
    func loadUserAncestorAllowlistResult() -> DatabaseLoadResult<AncestorAllowlistEntry>
    func loadUserJailRulesResult() -> DatabaseLoadResult<JailRule>
    func saveUserRules(_ rules: [FAARule])
    func saveUserAllowlist(_ entries: [AllowlistEntry])
    func saveUserAncestorAllowlist(_ entries: [AncestorAllowlistEntry])
    func saveUserJailRules(_ rules: [JailRule])
}

// MARK: - PolicyRepository

final class PolicyRepository: @unchecked Sendable {
    private struct State {
        var managedRules: [FAARule] = []
        var userRules: [FAARule] = []
        var xprotectEntries: [AllowlistEntry] = []
        var managedAllowlist: [AllowlistEntry] = []
        var userAllowlist: [AllowlistEntry] = []
        var managedAncestorAllowlist: [AncestorAllowlistEntry] = []
        var userAncestorAllowlist: [AncestorAllowlistEntry] = []
        var userJailRules: [JailRule] = []
        var pendingSuspectUserRules: [FAARule]?
        var pendingSuspectUserAllowlist: [AllowlistEntry]?
    }

    private let storage: OSAllocatedUnfairLock<State>
    private let database: PolicyDatabaseProtocol

    init(
        database: PolicyDatabaseProtocol,
        managedRules: [FAARule] = [],
        managedAllowlist: [AllowlistEntry] = [],
        xprotectEntries: [AllowlistEntry] = []
    ) {
        var initialState = State()
        initialState.managedRules = managedRules
        initialState.managedAllowlist = managedAllowlist
        initialState.xprotectEntries = xprotectEntries

        switch database.loadUserRulesResult() {
        case .ok(let rules):
            initialState.userRules = rules
        case .suspect(let rules):
            initialState.pendingSuspectUserRules = rules
            logger.warning("PolicyRepository: Signature issue for user_rules — awaiting GUI resolution")
        }

        switch database.loadUserAllowlistResult() {
        case .ok(let entries):
            initialState.userAllowlist = entries
        case .suspect(let entries):
            initialState.pendingSuspectUserAllowlist = entries
            logger.warning("PolicyRepository: Signature issue for user_allowlist — awaiting GUI resolution")
        }

        switch database.loadUserAncestorAllowlistResult() {
        case .ok(let entries):
            initialState.userAncestorAllowlist = entries
        case .suspect(let entries):
            // Ancestor allowlist entries bypass all policy rules, so tampering is
            // high impact. Silently discard and log — the user will notice that their
            // ancestor entries are gone and can re-add them after investigating.
            logger.warning("PolicyRepository: Signature issue for user_ancestor_allowlist — discarding \(entries.count) suspect entry/entries")
        }

        switch database.loadUserJailRulesResult() {
        case .ok(let rules):
            initialState.userJailRules = rules
        case .suspect(let rules):
            logger.warning("PolicyRepository: Signature issue for user_jail_rules — discarding \(rules.count) suspect rule(s)")
        }

        self.storage = OSAllocatedUnfairLock(initialState: initialState)
        self.database = database
    }

    // MARK: - Resync

    func resync(
        managedRules: [FAARule],
        managedAllowlist: [AllowlistEntry],
        xprotectEntries: [AllowlistEntry]
    ) {
        storage.withLock {
            $0.managedRules = managedRules
            $0.managedAllowlist = managedAllowlist
            $0.xprotectEntries = xprotectEntries
        }
    }

    @discardableResult
    func updateXProtectEntries(_ entries: [AllowlistEntry]) -> Bool {
        storage.withLock { state in
            let currentPaths = Set(state.xprotectEntries.map(\.processPath))
            let newPaths = Set(entries.map(\.processPath))
            guard currentPaths != newPaths else { return false }
            state.xprotectEntries = entries
            return true
        }
    }

    // MARK: - Merged views

    func mergedRules() -> [FAARule] {
        storage.withLock { faaPolicy + $0.managedRules + $0.userRules }
    }

    func mergedAllowlist() -> [AllowlistEntry] {
        storage.withLock { baselineAllowlist + $0.xprotectEntries + $0.managedAllowlist + $0.userAllowlist }
    }

    func mergedAncestorAllowlist() -> [AncestorAllowlistEntry] {
        storage.withLock { $0.managedAncestorAllowlist + $0.userAncestorAllowlist }
    }

    func mergedJailRules() -> [JailRule] {
        storage.withLock { $0.userJailRules }
    }

    // MARK: - Rule mutations

    func addRule(_ rule: FAARule) {
        let rules = storage.withLock { state -> [FAARule] in
            state.userRules.append(rule)
            return state.userRules
        }
        database.saveUserRules(rules)
    }

    func updateRule(_ rule: FAARule) {
        let rules: [FAARule]? = storage.withLock { state in
            guard let index = state.userRules.firstIndex(where: { $0.id == rule.id }) else { return nil }
            state.userRules[index] = rule
            return state.userRules
        }
        guard let rules else {
            logger.error("PolicyRepository: updateRule — rule \(rule.id.uuidString, privacy: .public) not found")
            return
        }
        database.saveUserRules(rules)
    }

    func removeRule(ruleID: UUID) {
        let rules = storage.withLock { state -> [FAARule] in
            state.userRules.removeAll { $0.id == ruleID }
            return state.userRules
        }
        database.saveUserRules(rules)
    }

    // MARK: - Allowlist mutations

    func addAllowlistEntry(_ entry: AllowlistEntry) {
        let entries = storage.withLock { state -> [AllowlistEntry] in
            state.userAllowlist.append(entry)
            return state.userAllowlist
        }
        database.saveUserAllowlist(entries)
    }

    func removeAllowlistEntry(entryID: UUID) {
        let entries = storage.withLock { state -> [AllowlistEntry] in
            state.userAllowlist.removeAll { $0.id == entryID }
            return state.userAllowlist
        }
        database.saveUserAllowlist(entries)
    }

    // MARK: - Ancestor allowlist mutations

    func addAncestorAllowlistEntry(_ entry: AncestorAllowlistEntry) {
        let entries = storage.withLock { state -> [AncestorAllowlistEntry] in
            state.userAncestorAllowlist.append(entry)
            return state.userAncestorAllowlist
        }
        database.saveUserAncestorAllowlist(entries)
    }

    func removeAncestorAllowlistEntry(entryID: UUID) {
        let entries = storage.withLock { state -> [AncestorAllowlistEntry] in
            state.userAncestorAllowlist.removeAll { $0.id == entryID }
            return state.userAncestorAllowlist
        }
        database.saveUserAncestorAllowlist(entries)
    }

    // MARK: - Jail rule mutations

    func addJailRule(_ rule: JailRule) {
        let rules = storage.withLock { state -> [JailRule] in
            state.userJailRules.append(rule)
            return state.userJailRules
        }
        database.saveUserJailRules(rules)
    }

    func updateJailRule(_ rule: JailRule) {
        let rules: [JailRule]? = storage.withLock { state in
            guard let index = state.userJailRules.firstIndex(where: { $0.id == rule.id }) else { return nil }
            state.userJailRules[index] = rule
            return state.userJailRules
        }
        guard let rules else {
            logger.error("PolicyRepository: updateJailRule — rule \(rule.id.uuidString, privacy: .public) not found")
            return
        }
        database.saveUserJailRules(rules)
    }

    func removeJailRule(ruleID: UUID) {
        let rules = storage.withLock { state -> [JailRule] in
            state.userJailRules.removeAll { $0.id == ruleID }
            return state.userJailRules
        }
        database.saveUserJailRules(rules)
    }

    // MARK: - Signature issue

    var hasPendingSignatureIssue: Bool {
        storage.withLock { $0.pendingSuspectUserRules != nil || $0.pendingSuspectUserAllowlist != nil }
    }

    func pendingSignatureIssueNotification() -> SignatureIssueNotification? {
        storage.withLock { state -> SignatureIssueNotification? in
            guard state.pendingSuspectUserRules != nil || state.pendingSuspectUserAllowlist != nil else { return nil }
            guard let rulesData = try? JSONEncoder().encode(state.pendingSuspectUserRules ?? []),
                  let allowlistData = try? JSONEncoder().encode(state.pendingSuspectUserAllowlist ?? []) else {
                logger.fault("PolicyRepository: Failed to encode suspect data for signature issue notification")
                return nil
            }
            return SignatureIssueNotification(
                suspectRulesData: rulesData as NSData,
                suspectAllowlistData: allowlistData as NSData
            )
        }
    }

    func resolveSignatureIssue(approved: Bool) {
        let (rules, allowlist): ([FAARule], [AllowlistEntry]) = storage.withLock { state in
            let rules = approved ? (state.pendingSuspectUserRules ?? []) : []
            let allowlist = approved ? (state.pendingSuspectUserAllowlist ?? []) : []
            state.pendingSuspectUserRules = nil
            state.pendingSuspectUserAllowlist = nil
            state.userRules = rules
            state.userAllowlist = allowlist
            return (rules, allowlist)
        }
        database.saveUserRules(rules)
        database.saveUserAllowlist(allowlist)
    }

    // MARK: - Encoded views for broadcasting

    func encodedManagedRules() -> NSData {
        let rules = storage.withLock { $0.managedRules }
        guard let data = try? JSONEncoder().encode(rules) else {
            fatalError("PolicyRepository: Failed to encode managed rules — this is a bug")
        }
        return data as NSData
    }

    func encodedUserRules() -> NSData {
        let rules = storage.withLock { $0.userRules }
        guard let data = try? JSONEncoder().encode(rules) else {
            fatalError("PolicyRepository: Failed to encode user rules — this is a bug")
        }
        return data as NSData
    }

    func encodedManagedAllowlist() -> NSData {
        let entries = storage.withLock { $0.managedAllowlist }
        guard let data = try? JSONEncoder().encode(entries) else {
            fatalError("PolicyRepository: Failed to encode managed allowlist — this is a bug")
        }
        return data as NSData
    }

    func encodedUserAllowlist() -> NSData {
        let entries = storage.withLock { $0.userAllowlist }
        guard let data = try? JSONEncoder().encode(entries) else {
            fatalError("PolicyRepository: Failed to encode user allowlist — this is a bug")
        }
        return data as NSData
    }

    func encodedManagedAncestorAllowlist() -> NSData {
        let entries = storage.withLock { $0.managedAncestorAllowlist }
        guard let data = try? JSONEncoder().encode(entries) else {
            fatalError("PolicyRepository: Failed to encode managed ancestor allowlist — this is a bug")
        }
        return data as NSData
    }

    func encodedUserAncestorAllowlist() -> NSData {
        let entries = storage.withLock { $0.userAncestorAllowlist }
        guard let data = try? JSONEncoder().encode(entries) else {
            fatalError("PolicyRepository: Failed to encode user ancestor allowlist — this is a bug")
        }
        return data as NSData
    }

    func encodedUserJailRules() -> NSData {
        let rules = storage.withLock { $0.userJailRules }
        guard let data = try? JSONEncoder().encode(rules) else {
            fatalError("PolicyRepository: Failed to encode user jail rules — this is a bug")
        }
        return data as NSData
    }
}
