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

// MARK: - DatabaseLoadResult

enum DatabaseLoadResult<T> {
    case ok([T])
    case suspect([T])
}

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
                   allowed_ancestor_process_paths, allowed_ancestor_signatures
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
                 allowed_ancestor_process_paths, allowed_ancestor_signatures)
            VALUES (?, ?, ?, ?, ?, ?)
        """, bindings: [
            .text(rule.id.uuidString),
            .text(rule.protectedPathPrefix),
            .text(encodeStringArray(rule.allowedProcessPaths)),
            .text(encodeSignatureArray(rule.allowedSignatures)),
            .text(encodeStringArray(rule.allowedAncestorProcessPaths)),
            .text(encodeSignatureArray(rule.allowedAncestorSignatures)),
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
            allowedAncestorSignatures: decodeSignatureArray(columnText(stmt, 5))
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

    // MARK: - Signature verification

    private enum SignatureCheckResult {
        case verified
        case uninitialized
        case suspect
    }

    private func updateSignature(table: String, content: Data) {
        guard let signature = try? PolicySigner.sign(content) else {
            NSLog("Database: Failed to sign %@ content", table)
            return
        }
        execute(
            "INSERT OR REPLACE INTO data_signatures (table_name, signature) VALUES (?, ?)",
            bindings: [.text(table), .blob(signature)]
        )
    }

    private func tableHasRows(_ table: String) -> Bool {
        switch table {
        case "user_rules":    break
        case "user_allowlist": break
        default: preconditionFailure("Unexpected table name: \(table)")
        }
        var found = false
        query("SELECT 1 FROM \(table) LIMIT 1") { _ in found = true }
        return found
    }

    private func checkSignature(table: String, content: Data) -> SignatureCheckResult {
        var signature: Data?
        query("SELECT signature FROM data_signatures WHERE table_name = ?", bindings: [.text(table)]) { stmt in
            guard let blobPtr = sqlite3_column_blob(stmt, 0) else { return }
            let blobLen = sqlite3_column_bytes(stmt, 0)
            signature = Data(bytes: blobPtr, count: Int(blobLen))
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
        do {
            try PolicySigner.verify(content, signature: sig)
            return .verified
        } catch {
            NSLog("Database: Signature verification FAILED for %@ (%@)", table, "\(error)")
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
}
