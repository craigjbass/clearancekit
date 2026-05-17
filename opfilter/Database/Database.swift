//
//  Database.swift
//  opfilter
//
//  SQLite-backed persistent store for user rules and allowlist entries.
//  Replaces the previous JSON file storage while maintaining ECDSA signature
//  verification via PolicySigner.
//

import Foundation
import SQLite3

private let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

// MARK: - SQLiteBinding

enum SQLiteBinding {
    case text(String)
    case int(Int)
    case blob(Data)
    case null
}

// MARK: - Database

final class Database {
    let directory: URL
    private var db: OpaquePointer?

    init(directory: URL) {
        self.directory = directory

        do {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            fatalError("Database: Failed to create directory: \(error)")
        }

        let dbPath = directory.appendingPathComponent("store.db").path
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(dbPath, &db, flags, nil) == SQLITE_OK else {
            fatalError("Database: Failed to open at \(dbPath): \(errorMessage)")
        }

        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: dbPath
        )

        execute("PRAGMA journal_mode=WAL")
        execute("PRAGMA foreign_keys=ON")

        runMigrations()
        migrateAclIfNeeded()
    }

    deinit {
        sqlite3_close(db)
    }

    // MARK: - SQL primitives

    func execute(_ sql: String, bindings: [SQLiteBinding] = []) {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            fatalError("Database: Prepare failed for: \(sql) — \(errorMessage)")
        }
        defer { sqlite3_finalize(stmt) }
        applyBindings(stmt!, bindings)
        let result = sqlite3_step(stmt)
        guard result == SQLITE_DONE || result == SQLITE_ROW else {
            fatalError("Database: Execute failed for: \(sql) — \(errorMessage)")
        }
    }

    func query(_ sql: String, bindings: [SQLiteBinding] = [], row: (OpaquePointer) -> Void) {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            fatalError("Database: Prepare failed for: \(sql) — \(errorMessage)")
        }
        defer { sqlite3_finalize(stmt) }
        applyBindings(stmt!, bindings)
        while sqlite3_step(stmt) == SQLITE_ROW {
            row(stmt!)
        }
    }

    func inTransaction(_ body: () -> Void) {
        execute("BEGIN TRANSACTION")
        body()
        execute("COMMIT")
    }

    private func applyBindings(_ stmt: OpaquePointer, _ bindings: [SQLiteBinding]) {
        for (index, binding) in bindings.enumerated() {
            let col = Int32(index + 1)
            switch binding {
            case .text(let s):
                s.withCString { cStr in
                    checkBind(sqlite3_bind_text(stmt, col, cStr, -1, sqliteTransient))
                }
            case .int(let i):
                checkBind(sqlite3_bind_int64(stmt, col, Int64(i)))
            case .blob(let data):
                data.withUnsafeBytes { ptr in
                    checkBind(sqlite3_bind_blob(stmt, col, ptr.baseAddress, Int32(data.count), sqliteTransient))
                }
            case .null:
                checkBind(sqlite3_bind_null(stmt, col))
            }
        }
    }

    private func checkBind(_ result: Int32) {
        guard result == SQLITE_OK else {
            fatalError("Database: Bind failed with code \(result): \(errorMessage)")
        }
    }

    private var errorMessage: String {
        String(cString: sqlite3_errmsg(db))
    }

    // MARK: - Migrations

    private func runMigrations() {
        execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
        """)

        let applied = appliedMigrationVersions()
        for migration in allMigrations {
            guard !applied.contains(migration.version) else { continue }
            NSLog("Database: Running migration %d: %@", migration.version, migration.name)
            migration.up(self)
            execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                bindings: [.int(migration.version), .text(ISO8601DateFormatter().string(from: Date()))]
            )
            NSLog("Database: Completed migration %d", migration.version)
        }
    }

    private func appliedMigrationVersions() -> Set<Int> {
        var versions: Set<Int> = []
        query("SELECT version FROM schema_migrations") { stmt in
            versions.insert(Int(sqlite3_column_int64(stmt, 0)))
        }
        return versions
    }

    // MARK: - User Rules

    func loadUserRulesResult() -> DatabaseLoadResult<FAARule> {
        var rules: [FAARule] = []
        query("""
            SELECT id, protected_path_prefix,
                   allowed_process_paths, allowed_signatures,
                   allowed_ancestor_process_paths, allowed_ancestor_signatures,
                   enforce_on_write_only, require_valid_signing,
                   authorized_signatures, requires_authorization,
                   authorization_session_duration
            FROM user_rules ORDER BY rowid
        """) { stmt in
            if let rule = ruleFromRow(stmt) {
                rules.append(rule)
            }
        }
        switch checkSignature(table: "user_rules", content: canonicalRulesJSON(rules)) {
        case .verified, .uninitialized:
            NSLog("Database: Loaded %d user rule(s)", rules.count)
            return .ok(rules)
        case .suspect:
            NSLog("Database: Signature verification failed for user_rules — %d suspect rule(s)", rules.count)
            return .suspect(rules)
        }
    }

    func saveUserRules(_ rules: [FAARule]) {
        inTransaction {
            execute("DELETE FROM user_rules")
            for rule in rules {
                insertRule(rule)
            }
            updateSignature(table: "user_rules", content: canonicalRulesJSON(rules))
        }
    }

    private func insertRule(_ rule: FAARule) {
        execute("""
            INSERT INTO user_rules
                (id, protected_path_prefix,
                 allowed_process_paths, allowed_signatures,
                 allowed_ancestor_process_paths, allowed_ancestor_signatures,
                 enforce_on_write_only, require_valid_signing,
                 authorized_signatures, requires_authorization,
                 authorization_session_duration)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, bindings: [
            .text(rule.id.uuidString),
            .text(rule.protectedPathPrefix),
            .text(encodeStringArray(rule.allowedProcessPaths)),
            .text(encodeSignatureArray(rule.allowedSignatures)),
            .text(encodeStringArray(rule.allowedAncestorProcessPaths)),
            .text(encodeSignatureArray(rule.allowedAncestorSignatures)),
            .int(rule.enforceOnWriteOnly ? 1 : 0),
            .int(rule.requireValidSigning ? 1 : 0),
            .text(encodeSignatureArray(rule.authorizedSignatures)),
            .int(rule.requiresAuthorization ? 1 : 0),
            .int(Int(rule.authorizationSessionDuration)),
        ])
    }

    private func ruleFromRow(_ stmt: OpaquePointer) -> FAARule? {
        let uuidString = columnText(stmt, 0)
        guard let id = UUID(uuidString: uuidString) else {
            NSLog("Database: Skipping rule row with invalid UUID '%@'", uuidString)
            return nil
        }
        return FAARule(
            id: id,
            protectedPathPrefix: columnText(stmt, 1),
            allowedProcessPaths: decodeStringArray(columnText(stmt, 2)),
            allowedSignatures: decodeSignatureArray(columnText(stmt, 3)),
            allowedAncestorProcessPaths: decodeStringArray(columnText(stmt, 4)),
            allowedAncestorSignatures: decodeSignatureArray(columnText(stmt, 5)),
            enforceOnWriteOnly: sqlite3_column_int(stmt, 6) != 0,
            requireValidSigning: sqlite3_column_int(stmt, 7) != 0,
            authorizedSignatures: decodeSignatureArray(columnText(stmt, 8)),
            requiresAuthorization: sqlite3_column_int(stmt, 9) != 0,
            authorizationSessionDuration: TimeInterval(sqlite3_column_int64(stmt, 10))
        )
    }

    // MARK: - User Allowlist

    func loadUserAllowlistResult() -> DatabaseLoadResult<AllowlistEntry> {
        var entries: [AllowlistEntry] = []
        query("""
            SELECT id, signing_id, process_path, platform_binary, team_id
            FROM user_allowlist ORDER BY rowid
        """) { stmt in
            if let entry = allowlistEntryFromRow(stmt) {
                entries.append(entry)
            }
        }
        switch checkSignature(table: "user_allowlist", content: canonicalAllowlistJSON(entries)) {
        case .verified, .uninitialized:
            NSLog("Database: Loaded %d user allowlist entry/entries", entries.count)
            return .ok(entries)
        case .suspect:
            NSLog("Database: Signature verification failed for user_allowlist — %d suspect entry/entries", entries.count)
            return .suspect(entries)
        }
    }

    func saveUserAllowlist(_ entries: [AllowlistEntry]) {
        inTransaction {
            execute("DELETE FROM user_allowlist")
            for entry in entries {
                insertAllowlistEntry(entry)
            }
            updateSignature(table: "user_allowlist", content: canonicalAllowlistJSON(entries))
        }
    }

    private func insertAllowlistEntry(_ entry: AllowlistEntry) {
        execute("""
            INSERT INTO user_allowlist (id, signing_id, process_path, platform_binary, team_id)
            VALUES (?, ?, ?, ?, ?)
        """, bindings: [
            .text(entry.id.uuidString),
            .text(entry.signingID),
            .text(entry.processPath),
            .int(entry.platformBinary ? 1 : 0),
            .text(entry.teamID),
        ])
    }

    private func allowlistEntryFromRow(_ stmt: OpaquePointer) -> AllowlistEntry? {
        let uuidString = columnText(stmt, 0)
        guard let id = UUID(uuidString: uuidString) else {
            NSLog("Database: Skipping allowlist row with invalid UUID '%@'", uuidString)
            return nil
        }
        return AllowlistEntry(
            id: id,
            signingID: columnText(stmt, 1),
            processPath: columnText(stmt, 2),
            platformBinary: sqlite3_column_int(stmt, 3) != 0,
            teamID: columnText(stmt, 4)
        )
    }

    // MARK: - User Ancestor Allowlist

    func loadUserAncestorAllowlistResult() -> DatabaseLoadResult<AncestorAllowlistEntry> {
        var entries: [AncestorAllowlistEntry] = []
        query("""
            SELECT id, signing_id, process_path, platform_binary, team_id
            FROM user_ancestor_allowlist ORDER BY rowid
        """) { stmt in
            if let entry = ancestorAllowlistEntryFromRow(stmt) {
                entries.append(entry)
            }
        }
        switch checkSignature(table: "user_ancestor_allowlist", content: canonicalAncestorAllowlistJSON(entries)) {
        case .verified, .uninitialized:
            NSLog("Database: Loaded %d user ancestor allowlist entry/entries", entries.count)
            return .ok(entries)
        case .suspect:
            NSLog("Database: Signature verification failed for user_ancestor_allowlist — %d suspect entry/entries", entries.count)
            return .suspect(entries)
        }
    }

    func saveUserAncestorAllowlist(_ entries: [AncestorAllowlistEntry]) {
        inTransaction {
            execute("DELETE FROM user_ancestor_allowlist")
            for entry in entries {
                insertAncestorAllowlistEntry(entry)
            }
            updateSignature(table: "user_ancestor_allowlist", content: canonicalAncestorAllowlistJSON(entries))
        }
    }

    private func insertAncestorAllowlistEntry(_ entry: AncestorAllowlistEntry) {
        execute("""
            INSERT INTO user_ancestor_allowlist (id, signing_id, process_path, platform_binary, team_id)
            VALUES (?, ?, ?, ?, ?)
        """, bindings: [
            .text(entry.id.uuidString),
            .text(entry.signingID),
            .text(entry.processPath),
            .int(entry.platformBinary ? 1 : 0),
            .text(entry.teamID),
        ])
    }

    private func ancestorAllowlistEntryFromRow(_ stmt: OpaquePointer) -> AncestorAllowlistEntry? {
        let uuidString = columnText(stmt, 0)
        guard let id = UUID(uuidString: uuidString) else {
            NSLog("Database: Skipping ancestor allowlist row with invalid UUID '%@'", uuidString)
            return nil
        }
        return AncestorAllowlistEntry(
            id: id,
            signingID: columnText(stmt, 1),
            processPath: columnText(stmt, 2),
            platformBinary: sqlite3_column_int(stmt, 3) != 0,
            teamID: columnText(stmt, 4)
        )
    }

    // MARK: - User Jail Rules

    func loadUserJailRulesResult() -> DatabaseLoadResult<JailRule> {
        var rules: [JailRule] = []
        query("""
            SELECT id, name, jailed_signature, allowed_path_prefixes
            FROM user_jail_rules ORDER BY rowid
        """) { stmt in
            if let rule = jailRuleFromRow(stmt) {
                rules.append(rule)
            }
        }
        switch checkSignature(table: "user_jail_rules", content: canonicalJailRulesJSON(rules)) {
        case .verified, .uninitialized:
            NSLog("Database: Loaded %d user jail rule(s)", rules.count)
            return .ok(rules)
        case .suspect:
            NSLog("Database: Signature verification failed for user_jail_rules — %d suspect rule(s)", rules.count)
            return .suspect(rules)
        }
    }

    func saveUserJailRules(_ rules: [JailRule]) {
        inTransaction {
            execute("DELETE FROM user_jail_rules")
            for rule in rules {
                insertJailRule(rule)
            }
            updateSignature(table: "user_jail_rules", content: canonicalJailRulesJSON(rules))
        }
    }

    private func insertJailRule(_ rule: JailRule) {
        execute("""
            INSERT INTO user_jail_rules (id, name, jailed_signature, allowed_path_prefixes)
            VALUES (?, ?, ?, ?)
        """, bindings: [
            .text(rule.id.uuidString),
            .text(rule.name),
            .text(encodeSignature(rule.jailedSignature)),
            .text(encodeStringArray(rule.allowedPathPrefixes)),
        ])
    }

    private func jailRuleFromRow(_ stmt: OpaquePointer) -> JailRule? {
        let uuidString = columnText(stmt, 0)
        guard let id = UUID(uuidString: uuidString) else {
            NSLog("Database: Skipping jail rule row with invalid UUID '%@'", uuidString)
            return nil
        }
        guard let signature = decodeSignature(columnText(stmt, 2)) else {
            NSLog("Database: Skipping jail rule row with invalid signature")
            return nil
        }
        return JailRule(
            id: id,
            name: columnText(stmt, 1),
            jailedSignature: signature,
            allowedPathPrefixes: decodeStringArray(columnText(stmt, 3))
        )
    }

    private func encodeSignature(_ sig: ProcessSignature) -> String {
        "\(sig.teamID):\(sig.signingID)"
    }

    private func decodeSignature(_ string: String) -> ProcessSignature? {
        guard let colonIndex = string.firstIndex(of: ":") else { return nil }
        let teamID = String(string[string.startIndex..<colonIndex])
        let signingID = String(string[string.index(after: colonIndex)...])
        return ProcessSignature(teamID: teamID, signingID: signingID)
    }

    private func canonicalJailRulesJSON(_ rules: [JailRule]) -> Data {
        let sorted = rules.sorted { $0.id.uuidString < $1.id.uuidString }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let encoded = try? encoder.encode(sorted) else {
            fatalError("Database: Failed to JSON-encode jail rules for signature — [JailRule] must always be encodable")
        }
        return encoded
    }

    // MARK: - Feature Flags

    func loadFeatureFlagsResult() -> DatabaseLoadResult<FeatureFlag> {
        var flags: [FeatureFlag] = []
        query("SELECT id, name, enabled FROM feature_flags ORDER BY rowid") { stmt in
            if let flag = featureFlagFromRow(stmt) {
                flags.append(flag)
            }
        }
        switch checkSignature(table: "feature_flags", content: canonicalFeatureFlagsJSON(flags)) {
        case .verified, .uninitialized:
            NSLog("Database: Loaded %d feature flag(s)", flags.count)
            return .ok(flags)
        case .suspect:
            NSLog("Database: Signature verification failed for feature_flags — %d suspect flag(s)", flags.count)
            return .suspect(flags)
        }
    }

    func saveFeatureFlags(_ flags: [FeatureFlag]) {
        inTransaction {
            execute("DELETE FROM feature_flags")
            for flag in flags {
                insertFeatureFlag(flag)
            }
            updateSignature(table: "feature_flags", content: canonicalFeatureFlagsJSON(flags))
        }
    }

    private func insertFeatureFlag(_ flag: FeatureFlag) {
        execute("""
            INSERT INTO feature_flags (id, name, enabled)
            VALUES (?, ?, ?)
        """, bindings: [
            .text(flag.id.uuidString),
            .text(flag.name),
            .int(flag.enabled ? 1 : 0),
        ])
    }

    private func featureFlagFromRow(_ stmt: OpaquePointer) -> FeatureFlag? {
        let uuidString = columnText(stmt, 0)
        guard let id = UUID(uuidString: uuidString) else {
            NSLog("Database: Skipping feature flag row with invalid UUID '%@'", uuidString)
            return nil
        }
        return FeatureFlag(
            id: id,
            name: columnText(stmt, 1),
            enabled: sqlite3_column_int(stmt, 2) != 0
        )
    }

    private func canonicalFeatureFlagsJSON(_ flags: [FeatureFlag]) -> Data {
        let sorted = flags.sorted { $0.id.uuidString < $1.id.uuidString }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let encoded = try? encoder.encode(sorted) else {
            fatalError("Database: Failed to JSON-encode feature flags for signature — [FeatureFlag] must always be encodable")
        }
        return encoded
    }

    // MARK: - Bundle Updater Signatures

    func loadBundleUpdaterSignaturesResult() -> DatabaseLoadResult<BundleUpdaterSignature> {
        var signatures: [BundleUpdaterSignature] = []
        query("SELECT id, team_id, signing_id FROM bundle_updater_signatures ORDER BY rowid") { stmt in
            let uuidString = columnText(stmt, 0)
            guard let id = UUID(uuidString: uuidString) else {
                NSLog("Database: Skipping bundle updater signature row with invalid UUID '%@'", uuidString)
                return
            }
            signatures.append(BundleUpdaterSignature(
                id: id,
                teamID: columnText(stmt, 1),
                signingID: columnText(stmt, 2)
            ))
        }
        switch checkSignature(table: "bundle_updater_signatures", content: canonicalBundleUpdaterSignaturesJSON(signatures)) {
        case .verified, .uninitialized:
            NSLog("Database: Loaded %d bundle updater signature(s)", signatures.count)
            return .ok(signatures)
        case .suspect:
            NSLog("Database: Signature verification failed for bundle_updater_signatures — discarding %d signature(s)", signatures.count)
            return .suspect(signatures)
        }
    }

    func saveBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature]) {
        inTransaction {
            execute("DELETE FROM bundle_updater_signatures")
            for signature in signatures {
                execute("""
                    INSERT INTO bundle_updater_signatures (id, team_id, signing_id)
                    VALUES (?, ?, ?)
                """, bindings: [
                    .text(signature.id.uuidString),
                    .text(signature.teamID),
                    .text(signature.signingID),
                ])
            }
            updateSignature(table: "bundle_updater_signatures", content: canonicalBundleUpdaterSignaturesJSON(signatures))
        }
    }

    private func canonicalBundleUpdaterSignaturesJSON(_ signatures: [BundleUpdaterSignature]) -> Data {
        let sorted = signatures.sorted { $0.id.uuidString < $1.id.uuidString }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let encoded = try? encoder.encode(sorted) else {
            fatalError("Database: Failed to JSON-encode bundle updater signatures — [BundleUpdaterSignature] must always be encodable")
        }
        return encoded
    }

    // MARK: - Signature verification

    private enum SignatureCheckResult {
        case verified
        case uninitialized
        case suspect
    }

    // MARK: - ACL migration

    /// Captures every signed table whose existing signature verifies under the
    /// current (about-to-be-rotated) key, rotates the signing key so the next
    /// load creates a fresh one bound to opfilter's explicit executable path,
    /// then re-signs every captured table with the new key. Tables whose
    /// signatures don't verify under the old key are left alone — they'll
    /// enter the existing `.suspect` flow on next load.
    private func migrateAclIfNeeded() {
        guard PolicySigner.aclMigrationVersion() < PolicySigner.currentAclVersion() else { return }

        let captured = captureAllVerifiableTableContent()

        PolicySigner.rotateKey()

        // Force creation of the new key now so re-sign uses it.
        _ = try? PolicySigner.loadOrCreateKey()

        inTransaction {
            for (table, content) in captured {
                updateSignature(table: table, content: content)
            }
        }

        PolicySigner.recordAclMigrationVersion()
        NSLog("Database: ACL migration v%d complete — re-signed %d table(s) with new key", PolicySigner.currentAclVersion(), captured.count)
    }

    private func captureAllVerifiableTableContent() -> [(String, Data)] {
        var captured: [(String, Data)] = []
        for (table, content) in allTablesWithCanonicalContent() {
            let signature = readSignatureBlob(table: table)
            guard let sig = signature else { continue }
            // Existing signatures (pre-epoch migration) are over `content`
            // alone; the new format is `content || epoch.bigEndian`. At v3
            // migration time the epoch column was just added with default 0,
            // so the legacy format applies for every row we encounter here.
            if PolicySigner.canVerify(content, signature: sig) {
                captured.append((table, content))
            }
        }
        return captured
    }

    private func readSignatureBlob(table: String) -> Data? {
        var signature: Data?
        query("SELECT signature FROM data_signatures WHERE table_name = ?", bindings: [.text(table)]) { stmt in
            guard let blobPtr = sqlite3_column_blob(stmt, 0) else { return }
            let blobLen = sqlite3_column_bytes(stmt, 0)
            signature = Data(bytes: blobPtr, count: Int(blobLen))
        }
        return signature
    }

    private func allTablesWithCanonicalContent() -> [(String, Data)] {
        var result: [(String, Data)] = []

        var rules: [FAARule] = []
        query("""
            SELECT id, protected_path_prefix,
                   allowed_process_paths, allowed_signatures,
                   allowed_ancestor_process_paths, allowed_ancestor_signatures,
                   enforce_on_write_only, require_valid_signing,
                   authorized_signatures, requires_authorization,
                   authorization_session_duration
            FROM user_rules ORDER BY rowid
        """) { stmt in
            if let rule = ruleFromRow(stmt) { rules.append(rule) }
        }
        result.append(("user_rules", canonicalRulesJSON(rules)))

        var allowlist: [AllowlistEntry] = []
        query("""
            SELECT id, signing_id, process_path, platform_binary, team_id
            FROM user_allowlist ORDER BY rowid
        """) { stmt in
            if let entry = allowlistEntryFromRow(stmt) { allowlist.append(entry) }
        }
        result.append(("user_allowlist", canonicalAllowlistJSON(allowlist)))

        var ancestor: [AncestorAllowlistEntry] = []
        query("""
            SELECT id, signing_id, process_path, platform_binary, team_id
            FROM user_ancestor_allowlist ORDER BY rowid
        """) { stmt in
            if let entry = ancestorAllowlistEntryFromRow(stmt) { ancestor.append(entry) }
        }
        result.append(("user_ancestor_allowlist", canonicalAncestorAllowlistJSON(ancestor)))

        var jail: [JailRule] = []
        query("""
            SELECT id, name, jailed_signature, allowed_path_prefixes
            FROM user_jail_rules ORDER BY rowid
        """) { stmt in
            if let rule = jailRuleFromRow(stmt) { jail.append(rule) }
        }
        result.append(("user_jail_rules", canonicalJailRulesJSON(jail)))

        var flags: [FeatureFlag] = []
        query("SELECT id, name, enabled FROM feature_flags ORDER BY rowid") { stmt in
            if let flag = featureFlagFromRow(stmt) { flags.append(flag) }
        }
        result.append(("feature_flags", canonicalFeatureFlagsJSON(flags)))

        var updaterSigs: [BundleUpdaterSignature] = []
        query("SELECT id, team_id, signing_id FROM bundle_updater_signatures ORDER BY rowid") { stmt in
            let uuidString = columnText(stmt, 0)
            guard let id = UUID(uuidString: uuidString) else { return }
            updaterSigs.append(BundleUpdaterSignature(
                id: id,
                teamID: columnText(stmt, 1),
                signingID: columnText(stmt, 2)
            ))
        }
        result.append(("bundle_updater_signatures", canonicalBundleUpdaterSignaturesJSON(updaterSigs)))

        return result
    }

    private func updateSignature(table: String, content: Data) {
        let diskEpoch = readDiskEpoch(table: table) ?? 0
        let keychainEpoch = EpochRatchet.epoch(forTable: table) ?? 0
        let newEpoch = max(diskEpoch, keychainEpoch) &+ 1
        guard let signature = try? PolicySigner.sign(signedPayload(content: content, epoch: newEpoch)) else {
            NSLog("Database: Failed to sign %@ content", table)
            return
        }
        execute(
            "INSERT OR REPLACE INTO data_signatures (table_name, signature, epoch) VALUES (?, ?, ?)",
            bindings: [.text(table), .blob(signature), .int(Int(bitPattern: UInt(newEpoch)))]
        )
        EpochRatchet.setEpoch(newEpoch, forTable: table)
    }

    private func readDiskEpoch(table: String) -> UInt64? {
        var epoch: UInt64?
        query("SELECT epoch FROM data_signatures WHERE table_name = ?", bindings: [.text(table)]) { stmt in
            epoch = UInt64(bitPattern: Int64(sqlite3_column_int64(stmt, 0)))
        }
        return epoch
    }

    private func signedPayload(content: Data, epoch: UInt64) -> Data {
        var payload = content
        var bigEndian = epoch.bigEndian
        withUnsafeBytes(of: &bigEndian) { raw in
            payload.append(contentsOf: raw)
        }
        return payload
    }

    private func tableHasRows(_ table: String) -> Bool {
        switch table {
        case "user_rules":              break
        case "user_allowlist":          break
        case "user_ancestor_allowlist": break
        case "user_jail_rules":         break
        case "feature_flags":           break
        case "bundle_updater_signatures": break
        default: preconditionFailure("Unexpected table name: \(table)")
        }
        var found = false
        query("SELECT 1 FROM \(table) LIMIT 1") { _ in found = true }
        return found
    }

    private func checkSignature(table: String, content: Data) -> SignatureCheckResult {
        var signature: Data?
        var diskEpoch: UInt64 = 0
        query("SELECT signature, epoch FROM data_signatures WHERE table_name = ?", bindings: [.text(table)]) { stmt in
            guard let blobPtr = sqlite3_column_blob(stmt, 0) else { return }
            let blobLen = sqlite3_column_bytes(stmt, 0)
            signature = Data(bytes: blobPtr, count: Int(blobLen))
            diskEpoch = UInt64(bitPattern: Int64(sqlite3_column_int64(stmt, 1)))
        }
        guard let sig = signature else {
            guard !tableHasRows(table) else {
                NSLog("Database: No signature for %@ but table has rows — treating as suspect", table)
                return .suspect
            }
            NSLog("Database: No signature for %@ — signing now", table)
            updateSignature(table: table, content: content)
            return .uninitialized
        }

        var verified = false
        do {
            try PolicySigner.verify(signedPayload(content: content, epoch: diskEpoch), signature: sig)
            verified = true
        } catch {
            // Backward-compat: pre-migration-011 signatures were produced over
            // `content` alone. Migration 011 defaults their epoch to 0; accept
            // such legacy signatures so a freshly-upgraded install still loads.
            // The next save upgrades the format to the epoch-bound signature.
            if diskEpoch == 0, (try? PolicySigner.verify(content, signature: sig)) != nil {
                NSLog("Database: Accepted legacy signature for %@ (will upgrade on next save)", table)
                verified = true
            }
        }
        guard verified else {
            NSLog("Database: Signature verification FAILED for %@", table)
            return .suspect
        }

        let keychainEpoch = EpochRatchet.epoch(forTable: table)
        switch EpochRatchet.verdict(diskEpoch: diskEpoch, keychainEpoch: keychainEpoch) {
        case .verified:
            return .verified
        case .replay:
            NSLog(
                "Database: Epoch ratchet mismatch for %@ — disk=%llu keychain=%llu, treating as suspect (replay)",
                table, diskEpoch, keychainEpoch ?? 0
            )
            return .suspect
        }
    }

    // MARK: - Helpers

    private func columnText(_ stmt: OpaquePointer, _ index: Int32) -> String {
        guard let cStr = sqlite3_column_text(stmt, index) else { return "" }
        return String(cString: cStr)
    }

    private func encodeStringArray(_ array: [String]) -> String {
        guard let encoded = try? JSONEncoder().encode(array),
              let string = String(data: encoded, encoding: .utf8) else {
            fatalError("Database: Failed to JSON-encode string array — [String] must always be encodable")
        }
        return string
    }

    private func decodeStringArray(_ json: String) -> [String] {
        guard let jsonData = json.data(using: .utf8),
              let array = try? JSONDecoder().decode([String].self, from: jsonData) else {
            NSLog("Database: Failed to decode string array from corrupt JSON — skipping values")
            return []
        }
        return array
    }

    private func encodeSignatureArray(_ sigs: [ProcessSignature]) -> String {
        guard let encoded = try? JSONEncoder().encode(sigs),
              let string = String(data: encoded, encoding: .utf8) else {
            fatalError("Database: Failed to JSON-encode signature array — [ProcessSignature] must always be encodable")
        }
        return string
    }

    private func decodeSignatureArray(_ json: String) -> [ProcessSignature] {
        guard let jsonData = json.data(using: .utf8),
              let array = try? JSONDecoder().decode([ProcessSignature].self, from: jsonData) else {
            NSLog("Database: Failed to decode signature array from corrupt JSON — skipping values")
            return []
        }
        return array
    }

    private func canonicalRulesJSON(_ rules: [FAARule]) -> Data {
        let sorted = rules.sorted { $0.id.uuidString < $1.id.uuidString }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let encoded = try? encoder.encode(sorted) else {
            fatalError("Database: Failed to JSON-encode rules for signature — [FAARule] must always be encodable")
        }
        return encoded
    }

    private func canonicalAllowlistJSON(_ entries: [AllowlistEntry]) -> Data {
        let sorted = entries.sorted { $0.id.uuidString < $1.id.uuidString }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let encoded = try? encoder.encode(sorted) else {
            fatalError("Database: Failed to JSON-encode allowlist for signature — [AllowlistEntry] must always be encodable")
        }
        return encoded
    }

    private func canonicalAncestorAllowlistJSON(_ entries: [AncestorAllowlistEntry]) -> Data {
        let sorted = entries.sorted { $0.id.uuidString < $1.id.uuidString }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let encoded = try? encoder.encode(sorted) else {
            fatalError("Database: Failed to JSON-encode ancestor allowlist for signature — [AncestorAllowlistEntry] must always be encodable")
        }
        return encoded
    }
}

// MARK: - PolicyDatabaseProtocol conformance

extension Database: PolicyDatabaseProtocol {}