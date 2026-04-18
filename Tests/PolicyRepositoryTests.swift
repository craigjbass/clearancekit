//
//  PolicyRepositoryTests.swift
//  clearancekitTests
//

import Testing
import Foundation

// MARK: - FakeDatabase

private final class FakeDatabase: PolicyDatabaseProtocol {
    var userRulesResult: DatabaseLoadResult<FAARule> = .ok([])
    var userAllowlistResult: DatabaseLoadResult<AllowlistEntry> = .ok([])
    var userAncestorAllowlistResult: DatabaseLoadResult<AncestorAllowlistEntry> = .ok([])
    var userJailRulesResult: DatabaseLoadResult<JailRule> = .ok([])
    var featureFlagsResult: DatabaseLoadResult<FeatureFlag> = .ok([])

    private(set) var savedRules: [FAARule] = []
    private(set) var savedAllowlist: [AllowlistEntry] = []
    private(set) var savedAncestorAllowlist: [AncestorAllowlistEntry] = []
    private(set) var savedJailRules: [JailRule] = []
    private(set) var savedFeatureFlags: [FeatureFlag] = []

    func loadUserRulesResult() -> DatabaseLoadResult<FAARule> { userRulesResult }
    func loadUserAllowlistResult() -> DatabaseLoadResult<AllowlistEntry> { userAllowlistResult }
    func loadUserAncestorAllowlistResult() -> DatabaseLoadResult<AncestorAllowlistEntry> { userAncestorAllowlistResult }
    func loadUserJailRulesResult() -> DatabaseLoadResult<JailRule> { userJailRulesResult }
    func loadFeatureFlagsResult() -> DatabaseLoadResult<FeatureFlag> { featureFlagsResult }
    func loadBundleUpdaterSignaturesResult() -> DatabaseLoadResult<BundleUpdaterSignature> { .ok([]) }
    func saveUserRules(_ rules: [FAARule]) { savedRules = rules }
    func saveUserAllowlist(_ entries: [AllowlistEntry]) { savedAllowlist = entries }
    func saveUserAncestorAllowlist(_ entries: [AncestorAllowlistEntry]) { savedAncestorAllowlist = entries }
    func saveUserJailRules(_ rules: [JailRule]) { savedJailRules = rules }
    func saveFeatureFlags(_ flags: [FeatureFlag]) { savedFeatureFlags = flags }
    func saveBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature]) {}
}

// MARK: - Factories

private func makeRule(
    id: UUID = UUID(),
    prefix: String = "/protected",
    source: RuleSource = .user
) -> FAARule {
    FAARule(id: id, protectedPathPrefix: prefix, source: source)
}

private func makeEntry(id: UUID = UUID(), signingID: String = "com.example.app") -> AllowlistEntry {
    AllowlistEntry(id: id, signingID: signingID, processPath: "", platformBinary: false, teamID: "")
}

private func makeAncestorEntry(id: UUID = UUID(), signingID: String = "com.example.ancestor") -> AncestorAllowlistEntry {
    AncestorAllowlistEntry(id: id, signingID: signingID, processPath: "", platformBinary: false, teamID: "")
}

// MARK: - PolicyRepositoryTests

@Suite("PolicyRepository")
struct PolicyRepositoryTests {

    // MARK: - Initialisation

    @Test("loads user rules from database on init")
    func loadsUserRulesFromDatabase() {
        let rule = makeRule()
        let db = FakeDatabase()
        db.userRulesResult = .ok([rule])

        let repo = PolicyRepository(database: db)

        #expect(repo.mergedRules().contains { $0.id == rule.id })
    }

    @Test("loads user allowlist from database on init")
    func loadsUserAllowlistFromDatabase() {
        let entry = makeEntry()
        let db = FakeDatabase()
        db.userAllowlistResult = .ok([entry])

        let repo = PolicyRepository(database: db)

        #expect(repo.mergedAllowlist().contains { $0.id == entry.id })
    }

    @Test("loads user ancestor allowlist from database on init")
    func loadsUserAncestorAllowlistFromDatabase() {
        let entry = makeAncestorEntry()
        let db = FakeDatabase()
        db.userAncestorAllowlistResult = .ok([entry])

        let repo = PolicyRepository(database: db)

        #expect(repo.mergedAncestorAllowlist().contains { $0.id == entry.id })
    }

    @Test("suspect user rules set pending issue flag and clear active rules")
    func suspectUserRulesSetPendingIssue() {
        let rule = makeRule()
        let db = FakeDatabase()
        db.userRulesResult = .suspect([rule])

        let repo = PolicyRepository(database: db)

        #expect(repo.hasPendingSignatureIssue)
        #expect(!repo.mergedRules().contains { $0.id == rule.id })
    }

    @Test("suspect user allowlist sets pending issue flag and clear active entries")
    func suspectUserAllowlistSetsPendingIssue() {
        let entry = makeEntry()
        let db = FakeDatabase()
        db.userAllowlistResult = .suspect([entry])

        let repo = PolicyRepository(database: db)

        #expect(repo.hasPendingSignatureIssue)
        #expect(!repo.mergedAllowlist().contains { $0.id == entry.id })
    }

    @Test("suspect ancestor allowlist is silently discarded")
    func suspectAncestorAllowlistIsSilentlyDiscarded() {
        let entry = makeAncestorEntry()
        let db = FakeDatabase()
        db.userAncestorAllowlistResult = .suspect([entry])

        let repo = PolicyRepository(database: db)

        #expect(!repo.hasPendingSignatureIssue)
        #expect(repo.mergedAncestorAllowlist().isEmpty)
    }

    @Test("no pending signature issue when all loads succeed")
    func noPendingIssueOnCleanLoad() {
        let repo = PolicyRepository(database: FakeDatabase())

        #expect(!repo.hasPendingSignatureIssue)
        #expect(repo.pendingSignatureIssueNotification() == nil)
    }

    // MARK: - Merged views

    @Test("mergedRules prepends builtin policy before managed then user rules")
    func mergedRulesOrder() {
        let managed = makeRule(source: .mdm)
        let user = makeRule(source: .user)
        let repo = PolicyRepository(database: FakeDatabase(), managedRules: [managed])
        repo.addRule(user)

        let merged = repo.mergedRules()

        let builtinCount = faaPolicy.count
        #expect(merged.count == builtinCount + 2)
        #expect(merged[builtinCount].id == managed.id)
        #expect(merged[builtinCount + 1].id == user.id)
    }

    @Test("mergedAllowlist prepends baseline before xprotect then managed then user")
    func mergedAllowlistOrder() {
        let xprotect = makeEntry(signingID: "xprotect.entry")
        let managed = makeEntry(signingID: "managed.entry")
        let user = makeEntry(signingID: "user.entry")

        let repo = PolicyRepository(
            database: FakeDatabase(),
            managedAllowlist: [managed],
            xprotectEntries: [xprotect]
        )
        repo.addAllowlistEntry(user)

        let merged = repo.mergedAllowlist()
        let signingIDs = merged.map(\.signingID)

        let baselineCount = baselineAllowlist.count
        #expect(merged.count == baselineCount + 3)
        #expect(signingIDs[baselineCount] == "xprotect.entry")
        #expect(signingIDs[baselineCount + 1] == "managed.entry")
        #expect(signingIDs[baselineCount + 2] == "user.entry")
    }

    // MARK: - Rule mutations

    @Test("addRule appends to merged rules and persists")
    func addRuleAppendsAndPersists() {
        let db = FakeDatabase()
        let repo = PolicyRepository(database: db)
        let rule = makeRule()

        repo.addRule(rule)

        #expect(repo.mergedRules().contains { $0.id == rule.id })
        #expect(db.savedRules.contains { $0.id == rule.id })
    }

    @Test("updateRule replaces existing rule")
    func updateRuleReplaces() {
        let id = UUID()
        let original = makeRule(id: id, prefix: "/original")
        let db = FakeDatabase()
        db.userRulesResult = .ok([original])
        let repo = PolicyRepository(database: db)
        let updated = makeRule(id: id, prefix: "/updated")

        repo.updateRule(updated)

        let merged = repo.mergedRules()
        #expect(merged.contains { $0.id == id && $0.protectedPathPrefix == "/updated" })
        #expect(!merged.contains { $0.protectedPathPrefix == "/original" })
        #expect(db.savedRules.contains { $0.protectedPathPrefix == "/updated" })
    }

    @Test("updateRule with unknown ID is a no-op")
    func updateRuleUnknownIDIsNoOp() {
        let db = FakeDatabase()
        let repo = PolicyRepository(database: db)
        let unknown = makeRule(id: UUID(), prefix: "/unknown")

        repo.updateRule(unknown)

        #expect(!repo.mergedRules().contains { $0.id == unknown.id })
        #expect(db.savedRules.isEmpty)
    }

    @Test("removeRule deletes by ID")
    func removeRuleDeletesByID() {
        let rule = makeRule()
        let db = FakeDatabase()
        db.userRulesResult = .ok([rule])
        let repo = PolicyRepository(database: db)

        repo.removeRule(ruleID: rule.id)

        #expect(!repo.mergedRules().contains { $0.id == rule.id })
        #expect(db.savedRules.isEmpty)
    }

    // MARK: - Allowlist mutations

    @Test("addAllowlistEntry appends and persists")
    func addAllowlistEntryAppendsAndPersists() {
        let db = FakeDatabase()
        let repo = PolicyRepository(database: db)
        let entry = makeEntry()

        repo.addAllowlistEntry(entry)

        #expect(repo.mergedAllowlist().contains { $0.id == entry.id })
        #expect(db.savedAllowlist.contains { $0.id == entry.id })
    }

    @Test("removeAllowlistEntry deletes by ID")
    func removeAllowlistEntryDeletesByID() {
        let entry = makeEntry()
        let db = FakeDatabase()
        db.userAllowlistResult = .ok([entry])
        let repo = PolicyRepository(database: db)

        repo.removeAllowlistEntry(entryID: entry.id)

        #expect(!repo.mergedAllowlist().contains { $0.id == entry.id })
        #expect(db.savedAllowlist.isEmpty)
    }

    // MARK: - Ancestor allowlist mutations

    @Test("addAncestorAllowlistEntry appends and persists")
    func addAncestorAllowlistEntryAppendsAndPersists() {
        let db = FakeDatabase()
        let repo = PolicyRepository(database: db)
        let entry = makeAncestorEntry()

        repo.addAncestorAllowlistEntry(entry)

        #expect(repo.mergedAncestorAllowlist().contains { $0.id == entry.id })
        #expect(db.savedAncestorAllowlist.contains { $0.id == entry.id })
    }

    @Test("removeAncestorAllowlistEntry deletes by ID")
    func removeAncestorAllowlistEntryDeletesByID() {
        let entry = makeAncestorEntry()
        let db = FakeDatabase()
        db.userAncestorAllowlistResult = .ok([entry])
        let repo = PolicyRepository(database: db)

        repo.removeAncestorAllowlistEntry(entryID: entry.id)

        #expect(!repo.mergedAncestorAllowlist().contains { $0.id == entry.id })
        #expect(db.savedAncestorAllowlist.isEmpty)
    }

    // MARK: - Resync

    @Test("resync replaces managed state")
    func resyncReplacesManagedState() {
        let initial = makeRule(prefix: "/before", source: .mdm)
        let repo = PolicyRepository(database: FakeDatabase(), managedRules: [initial])
        let replacement = makeRule(prefix: "/after", source: .mdm)

        repo.resync(managedRules: [replacement], managedAllowlist: [], managedJailRules: [], xprotectEntries: [])

        let merged = repo.mergedRules()
        #expect(!merged.contains { $0.id == initial.id })
        #expect(merged.contains { $0.id == replacement.id })
    }

    @Test("updateXProtectEntries returns true when paths change")
    func updateXProtectEntriesReturnsTrueOnChange() {
        let repo = PolicyRepository(database: FakeDatabase())
        let entry = makeEntry(signingID: "")

        let changed = repo.updateXProtectEntries([entry])

        #expect(changed)
    }

    @Test("updateXProtectEntries returns false when paths are unchanged")
    func updateXProtectEntriesReturnsFalseWhenUnchanged() {
        let entry = makeEntry(signingID: "")
        let repo = PolicyRepository(database: FakeDatabase(), xprotectEntries: [entry])

        let changed = repo.updateXProtectEntries([entry])

        #expect(!changed)
    }

    // MARK: - Signature issue resolution

    @Test("resolveSignatureIssue approved restores suspect rules")
    func resolveSignatureIssueApprovedRestoresRules() {
        let suspect = makeRule()
        let db = FakeDatabase()
        db.userRulesResult = .suspect([suspect])
        let repo = PolicyRepository(database: db)

        repo.resolveSignatureIssue(approved: true)

        #expect(repo.mergedRules().contains { $0.id == suspect.id })
        #expect(!repo.hasPendingSignatureIssue)
        #expect(db.savedRules.contains { $0.id == suspect.id })
    }

    @Test("resolveSignatureIssue rejected clears user rules")
    func resolveSignatureIssueRejectedClearsRules() {
        let suspect = makeRule()
        let db = FakeDatabase()
        db.userRulesResult = .suspect([suspect])
        let repo = PolicyRepository(database: db)

        repo.resolveSignatureIssue(approved: false)

        #expect(!repo.mergedRules().contains { $0.id == suspect.id })
        #expect(!repo.hasPendingSignatureIssue)
        #expect(db.savedRules.isEmpty)
    }

    @Test("resolveSignatureIssue approved restores suspect allowlist")
    func resolveSignatureIssueApprovedRestoresAllowlist() {
        let suspect = makeEntry()
        let db = FakeDatabase()
        db.userAllowlistResult = .suspect([suspect])
        let repo = PolicyRepository(database: db)

        repo.resolveSignatureIssue(approved: true)

        #expect(repo.mergedAllowlist().contains { $0.id == suspect.id })
        #expect(!repo.hasPendingSignatureIssue)
    }

    @Test("pendingSignatureIssueNotification returns nil when no issue pending")
    func pendingNotificationNilWhenNoIssue() {
        let repo = PolicyRepository(database: FakeDatabase())

        #expect(repo.pendingSignatureIssueNotification() == nil)
    }

    @Test("pendingSignatureIssueNotification returns notification when issue pending")
    func pendingNotificationPresentWhenIssuePending() {
        let suspect = makeRule()
        let db = FakeDatabase()
        db.userRulesResult = .suspect([suspect])
        let repo = PolicyRepository(database: db)

        #expect(repo.pendingSignatureIssueNotification() != nil)
    }

    // MARK: - Encoded views

    @Test("encodedUserRules round-trips through JSON")
    func encodedUserRulesRoundTrips() throws {
        let rule = makeRule()
        let db = FakeDatabase()
        let repo = PolicyRepository(database: db)
        repo.addRule(rule)

        let data = repo.encodedUserRules() as Data
        let decoded = try JSONDecoder().decode([FAARule].self, from: data)

        #expect(decoded.contains { $0.id == rule.id })
    }

    @Test("encodedManagedRules round-trips through JSON")
    func encodedManagedRulesRoundTrips() throws {
        let managed = makeRule(source: .mdm)
        let repo = PolicyRepository(database: FakeDatabase(), managedRules: [managed])

        let data = repo.encodedManagedRules() as Data
        let decoded = try JSONDecoder().decode([FAARule].self, from: data)

        #expect(decoded.contains { $0.id == managed.id })
    }
}
