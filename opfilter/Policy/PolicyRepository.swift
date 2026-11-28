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
    func loadFeatureFlagsResult() -> DatabaseLoadResult<FeatureFlag>
    func loadBundleUpdaterSignaturesResult() -> DatabaseLoadResult<BundleUpdaterSignature>
    func loadUserQuietListResult() -> DatabaseLoadResult<QuietListEntry>
    func saveUserRules(_ rules: [FAARule])
    func saveUserAllowlist(_ entries: [AllowlistEntry])
    func saveUserAncestorAllowlist(_ entries: [AncestorAllowlistEntry])
    func saveUserJailRules(_ rules: [JailRule])
    func saveFeatureFlags(_ flags: [FeatureFlag])
    func saveBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature])
    func saveUserQuietList(_ entries: [QuietListEntry])
}

// MARK: - PolicyRepository

final class PolicyRepository: @unchecked Sendable {
    /// Tables whose signature failed to verify, held back until the user
    /// approves or clears them. A nil table verified; an empty table is
    /// suspect and has no rows, and still needs a new signature.
    private struct SuspectTables {
        var userRules: [FAARule]?
        var userAllowlist: [AllowlistEntry]?
        var userAncestorAllowlist: [AncestorAllowlistEntry]?
        var userQuietList: [QuietListEntry]?
        var userJailRules: [JailRule]?
        var featureFlags: [FeatureFlag]?
        var bundleUpdaterSignatures: [BundleUpdaterSignature]?

        var isEmpty: Bool {
            userRules == nil
                && userAllowlist == nil
                && userAncestorAllowlist == nil
                && userQuietList == nil
                && userJailRules == nil
                && featureFlags == nil
                && bundleUpdaterSignatures == nil
        }

        /// The content that replaces each suspect table when the user
        /// clears the database: no rows, and protective feature flags.
        func cleared() -> SuspectTables {
            SuspectTables(
                userRules: userRules.map { _ in [] },
                userAllowlist: userAllowlist.map { _ in [] },
                userAncestorAllowlist: userAncestorAllowlist.map { _ in [] },
                userQuietList: userQuietList.map { _ in [] },
                userJailRules: userJailRules.map { _ in [] },
                featureFlags: featureFlags.map { _ in State.protectiveFeatureFlags },
                bundleUpdaterSignatures: bundleUpdaterSignatures.map { _ in [] }
            )
        }
    }

    private struct State {
        /// Used while the stored feature flags are suspect: MCP server off,
        /// bundle protection on, advanced mode off, and authentication
        /// required for each MCP connection.
        static let protectiveFeatureFlags = [
            FeatureFlag(id: FeatureFlagID.mcpServerEnabled, name: "mcp_server_enabled", enabled: false),
            FeatureFlag(id: FeatureFlagID.bundleProtectionEnabled, name: "bundle_protection_enabled", enabled: true),
            FeatureFlag(id: FeatureFlagID.advancedModeEnabled, name: "advanced_mode_enabled", enabled: false),
            FeatureFlag(id: FeatureFlagID.mcpConnectionAuthenticationRequired, name: "mcp_connection_authentication_required", enabled: true),
        ]

        var managedRules: [FAARule] = []
        var userRules: [FAARule] = []
        var xprotectEntries: [AllowlistEntry] = []
        var managedAllowlist: [AllowlistEntry] = []
        var userAllowlist: [AllowlistEntry] = []
        var managedAncestorAllowlist: [AncestorAllowlistEntry] = []
        var userAncestorAllowlist: [AncestorAllowlistEntry] = []
        var managedQuietList: [QuietListEntry] = []
        var userQuietList: [QuietListEntry] = []
        var managedJailRules: [JailRule] = []
        var userJailRules: [JailRule] = []
        var pendingSuspectTables = SuspectTables()
        var featureFlags: [FeatureFlag] = []
        var mcpEnabled: Bool = false
        var bundleProtectionEnabled: Bool = true
        var advancedModeEnabled: Bool = false
        var mcpConnectionAuthenticationRequired: Bool = true
        var bundleUpdaterSignatures: [BundleUpdaterSignature] = []

        mutating func adoptFeatureFlags(_ flags: [FeatureFlag]) {
            featureFlags = flags
            mcpEnabled = flags.first(where: { $0.id == FeatureFlagID.mcpServerEnabled })?.enabled ?? false
            bundleProtectionEnabled = flags.first(where: { $0.id == FeatureFlagID.bundleProtectionEnabled })?.enabled ?? true
            advancedModeEnabled = flags.first(where: { $0.id == FeatureFlagID.advancedModeEnabled })?.enabled ?? false
            // No migration seeds this row: inserting a row changes the signed
            // content of an existing feature_flags table. A missing row means
            // authentication is required, and the first save adds the row.
            mcpConnectionAuthenticationRequired = flags.first(where: { $0.id == FeatureFlagID.mcpConnectionAuthenticationRequired })?.enabled ?? true
        }
    }

    private let storage: OSAllocatedUnfairLock<State>
    private let database: PolicyDatabaseProtocol

    init(
        database: PolicyDatabaseProtocol,
        managedRules: [FAARule] = [],
        managedAllowlist: [AllowlistEntry] = [],
        managedQuietList: [QuietListEntry] = [],
        managedJailRules: [JailRule] = [],
        xprotectEntries: [AllowlistEntry] = []
    ) {
        var initialState = State()
        initialState.managedRules = managedRules
        initialState.managedAllowlist = managedAllowlist
        initialState.managedQuietList = managedQuietList
        initialState.managedJailRules = managedJailRules
        initialState.xprotectEntries = xprotectEntries

        // A suspect table stays inactive until the user approves it in the
        // GUI. Ancestor allowlist entries bypass all policy rules, so they
        // must never become active without that approval.
        switch database.loadUserRulesResult() {
        case .ok(let rules):
            initialState.userRules = rules
        case .suspect(let rules):
            initialState.pendingSuspectTables.userRules = rules
            logger.warning("PolicyRepository: Signature issue for user_rules — awaiting GUI resolution")
        }

        switch database.loadUserAllowlistResult() {
        case .ok(let entries):
            initialState.userAllowlist = entries
        case .suspect(let entries):
            initialState.pendingSuspectTables.userAllowlist = entries
            logger.warning("PolicyRepository: Signature issue for user_allowlist — awaiting GUI resolution")
        }

        switch database.loadUserAncestorAllowlistResult() {
        case .ok(let entries):
            initialState.userAncestorAllowlist = entries
        case .suspect(let entries):
            initialState.pendingSuspectTables.userAncestorAllowlist = entries
            logger.warning("PolicyRepository: Signature issue for user_ancestor_allowlist — awaiting GUI resolution")
        }

        switch database.loadUserQuietListResult() {
        case .ok(let entries):
            initialState.userQuietList = entries
        case .suspect(let entries):
            initialState.pendingSuspectTables.userQuietList = entries
            logger.warning("PolicyRepository: Signature issue for user_quiet_list — awaiting GUI resolution")
        }

        switch database.loadUserJailRulesResult() {
        case .ok(let rules):
            initialState.userJailRules = rules
        case .suspect(let rules):
            initialState.pendingSuspectTables.userJailRules = rules
            logger.warning("PolicyRepository: Signature issue for user_jail_rules — awaiting GUI resolution")
        }

        switch database.loadFeatureFlagsResult() {
        case .ok(let flags):
            initialState.adoptFeatureFlags(flags)
        case .suspect(let flags):
            initialState.pendingSuspectTables.featureFlags = flags
            initialState.adoptFeatureFlags(State.protectiveFeatureFlags)
            logger.warning("PolicyRepository: Signature issue for feature_flags — using protective flags, awaiting GUI resolution")
        }

        switch database.loadBundleUpdaterSignaturesResult() {
        case .ok(let signatures):
            initialState.bundleUpdaterSignatures = signatures
        case .suspect(let signatures):
            initialState.pendingSuspectTables.bundleUpdaterSignatures = signatures
            logger.warning("PolicyRepository: Signature issue for bundle_updater_signatures — awaiting GUI resolution")
        }

        self.storage = OSAllocatedUnfairLock(initialState: initialState)
        self.database = database
    }

    // MARK: - Resync

    func resync(
        managedRules: [FAARule],
        managedAllowlist: [AllowlistEntry],
        managedQuietList: [QuietListEntry],
        managedJailRules: [JailRule],
        xprotectEntries: [AllowlistEntry]
    ) {
        storage.withLock {
            $0.managedRules = managedRules
            $0.managedAllowlist = managedAllowlist
            $0.managedQuietList = managedQuietList
            $0.managedJailRules = managedJailRules
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

    func mergedQuietList() -> [QuietListEntry] {
        storage.withLock { baselineQuietList + $0.managedQuietList + $0.userQuietList }
    }

    func managedQuietList() -> [QuietListEntry] {
        storage.withLock { $0.managedQuietList }
    }

    func mergedAncestorAllowlist() -> [AncestorAllowlistEntry] {
        storage.withLock { $0.managedAncestorAllowlist + $0.userAncestorAllowlist }
    }

    func mergedJailRules() -> [JailRule] {
        storage.withLock { $0.managedJailRules + $0.userJailRules }
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

    // MARK: - Quiet list mutations

    func addQuietListEntry(_ entry: QuietListEntry) {
        let entries = storage.withLock { state -> [QuietListEntry] in
            state.userQuietList.append(entry)
            return state.userQuietList
        }
        database.saveUserQuietList(entries)
    }

    func removeQuietListEntry(entryID: UUID) {
        let entries = storage.withLock { state -> [QuietListEntry] in
            state.userQuietList.removeAll { $0.id == entryID }
            return state.userQuietList
        }
        database.saveUserQuietList(entries)
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

    // MARK: - Feature flags

    var mcpEnabled: Bool {
        storage.withLock { $0.mcpEnabled }
    }

    func setMCPEnabled(_ enabled: Bool) {
        let flags = storage.withLock { state -> [FeatureFlag] in
            state.mcpEnabled = enabled
            if let index = state.featureFlags.firstIndex(where: { $0.id == FeatureFlagID.mcpServerEnabled }) {
                state.featureFlags[index] = FeatureFlag(id: FeatureFlagID.mcpServerEnabled, name: "mcp_server_enabled", enabled: enabled)
            } else {
                state.featureFlags.append(FeatureFlag(id: FeatureFlagID.mcpServerEnabled, name: "mcp_server_enabled", enabled: enabled))
            }
            return state.featureFlags
        }
        database.saveFeatureFlags(flags)
    }

    var bundleProtectionEnabled: Bool {
        storage.withLock { $0.bundleProtectionEnabled }
    }

    func setBundleProtectionEnabled(_ enabled: Bool) {
        let flags = storage.withLock { state -> [FeatureFlag] in
            state.bundleProtectionEnabled = enabled
            if let index = state.featureFlags.firstIndex(where: { $0.id == FeatureFlagID.bundleProtectionEnabled }) {
                state.featureFlags[index] = FeatureFlag(id: FeatureFlagID.bundleProtectionEnabled, name: "bundle_protection_enabled", enabled: enabled)
            } else {
                state.featureFlags.append(FeatureFlag(id: FeatureFlagID.bundleProtectionEnabled, name: "bundle_protection_enabled", enabled: enabled))
            }
            return state.featureFlags
        }
        database.saveFeatureFlags(flags)
    }

    var advancedModeEnabled: Bool {
        storage.withLock { $0.advancedModeEnabled }
    }

    func setAdvancedModeEnabled(_ enabled: Bool) {
        let flags = storage.withLock { state -> [FeatureFlag] in
            state.advancedModeEnabled = enabled
            if let index = state.featureFlags.firstIndex(where: { $0.id == FeatureFlagID.advancedModeEnabled }) {
                state.featureFlags[index] = FeatureFlag(id: FeatureFlagID.advancedModeEnabled, name: "advanced_mode_enabled", enabled: enabled)
            } else {
                state.featureFlags.append(FeatureFlag(id: FeatureFlagID.advancedModeEnabled, name: "advanced_mode_enabled", enabled: enabled))
            }
            return state.featureFlags
        }
        database.saveFeatureFlags(flags)
    }

    var mcpConnectionAuthenticationRequired: Bool {
        storage.withLock { $0.mcpConnectionAuthenticationRequired }
    }

    func setMCPConnectionAuthenticationRequired(_ required: Bool) {
        let flag = FeatureFlag(id: FeatureFlagID.mcpConnectionAuthenticationRequired, name: "mcp_connection_authentication_required", enabled: required)
        let flags = storage.withLock { state -> [FeatureFlag] in
            state.mcpConnectionAuthenticationRequired = required
            if let index = state.featureFlags.firstIndex(where: { $0.id == FeatureFlagID.mcpConnectionAuthenticationRequired }) {
                state.featureFlags[index] = flag
            } else {
                state.featureFlags.append(flag)
            }
            return state.featureFlags
        }
        database.saveFeatureFlags(flags)
    }

    // MARK: - Bundle updater signatures

    func bundleUpdaterSignatures() -> [BundleUpdaterSignature] {
        storage.withLock { $0.bundleUpdaterSignatures }
    }

    func setBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature]) {
        storage.withLock { $0.bundleUpdaterSignatures = signatures }
        database.saveBundleUpdaterSignatures(signatures)
    }

    func encodedBundleUpdaterSignatures() -> NSData {
        let signatures = storage.withLock { $0.bundleUpdaterSignatures }
        guard let data = try? JSONEncoder().encode(signatures) else {
            fatalError("PolicyRepository: Failed to encode bundle updater signatures — this is a bug")
        }
        return data as NSData
    }

    // MARK: - Signature issue

    var hasPendingSignatureIssue: Bool {
        storage.withLock { !$0.pendingSuspectTables.isEmpty }
    }

    func pendingSignatureIssueNotification() -> SignatureIssueNotification? {
        let suspect = storage.withLock { $0.pendingSuspectTables }
        guard !suspect.isEmpty else { return nil }
        return SignatureIssueNotification(
            suspectRulesData: encodedSuspectTable(suspect.userRules),
            suspectAllowlistData: encodedSuspectTable(suspect.userAllowlist),
            suspectAncestorAllowlistData: encodedSuspectTable(suspect.userAncestorAllowlist),
            suspectQuietListData: encodedSuspectTable(suspect.userQuietList),
            suspectJailRulesData: encodedSuspectTable(suspect.userJailRules),
            suspectFeatureFlagsData: encodedSuspectTable(suspect.featureFlags),
            suspectBundleUpdaterSignaturesData: encodedSuspectTable(suspect.bundleUpdaterSignatures)
        )
    }

    /// Approve activates every suspect table and signs it with the current
    /// key. Reject replaces every suspect table with its cleared content and
    /// signs that. Tables that verified are not changed.
    func resolveSignatureIssue(approved: Bool) {
        let resolved = storage.withLock { state -> SuspectTables in
            let suspect = state.pendingSuspectTables
            state.pendingSuspectTables = SuspectTables()
            let resolved = approved ? suspect : suspect.cleared()
            if let rules = resolved.userRules { state.userRules = rules }
            if let entries = resolved.userAllowlist { state.userAllowlist = entries }
            if let entries = resolved.userAncestorAllowlist { state.userAncestorAllowlist = entries }
            if let entries = resolved.userQuietList { state.userQuietList = entries }
            if let rules = resolved.userJailRules { state.userJailRules = rules }
            if let flags = resolved.featureFlags { state.adoptFeatureFlags(flags) }
            if let signatures = resolved.bundleUpdaterSignatures { state.bundleUpdaterSignatures = signatures }
            return resolved
        }
        if let rules = resolved.userRules { database.saveUserRules(rules) }
        if let entries = resolved.userAllowlist { database.saveUserAllowlist(entries) }
        if let entries = resolved.userAncestorAllowlist { database.saveUserAncestorAllowlist(entries) }
        if let entries = resolved.userQuietList { database.saveUserQuietList(entries) }
        if let rules = resolved.userJailRules { database.saveUserJailRules(rules) }
        if let flags = resolved.featureFlags { database.saveFeatureFlags(flags) }
        if let signatures = resolved.bundleUpdaterSignatures { database.saveBundleUpdaterSignatures(signatures) }
    }

    private func encodedSuspectTable<Element: Encodable>(_ table: [Element]?) -> NSData? {
        guard let table else { return nil }
        guard let data = try? JSONEncoder().encode(table) else {
            fatalError("PolicyRepository: Failed to encode suspect \(Element.self) table — this is a bug")
        }
        return data as NSData
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

    func encodedManagedQuietList() -> NSData {
        let entries = storage.withLock { $0.managedQuietList }
        guard let data = try? JSONEncoder().encode(entries) else {
            fatalError("PolicyRepository: Failed to encode managed quiet list — this is a bug")
        }
        return data as NSData
    }

    func encodedUserQuietList() -> NSData {
        let entries = storage.withLock { $0.userQuietList }
        guard let data = try? JSONEncoder().encode(entries) else {
            fatalError("PolicyRepository: Failed to encode user quiet list — this is a bug")
        }
        return data as NSData
    }

    func encodedManagedJailRules() -> NSData {
        let rules = storage.withLock { $0.managedJailRules }
        guard let data = try? JSONEncoder().encode(rules) else {
            fatalError("PolicyRepository: Failed to encode managed jail rules — this is a bug")
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
