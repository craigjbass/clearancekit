//
//  DatabaseMigrations.swift
//  opfilter
//
//  Schema migration definitions. Each migration runs exactly once, tracked by
//  the schema_migrations table. Add new migrations to the end of allMigrations.
//

import Foundation
import SQLite3

// MARK: - Migration infrastructure

struct Migration {
    let version: Int
    let name: String
    let up: (Database) -> Void
}

let allMigrations: [Migration] = [
    Migration(version: 1, name: "Create tables and import from JSON", up: migration001CreateTablesAndImportJSON),
    Migration(version: 2, name: "Replace separate team/signing ID columns with combined signatures", up: migration002CombineSignatures),
]

// MARK: - Migration 001: Create tables and import existing JSON data

private func migration001CreateTablesAndImportJSON(_ db: Database) {
    db.execute("""
        CREATE TABLE user_rules (
            id TEXT PRIMARY KEY,
            protected_path_prefix TEXT NOT NULL,
            allowed_process_paths TEXT NOT NULL DEFAULT '[]',
            allowed_team_ids TEXT NOT NULL DEFAULT '[]',
            allowed_signing_ids TEXT NOT NULL DEFAULT '[]',
            allowed_ancestor_process_paths TEXT NOT NULL DEFAULT '[]',
            allowed_ancestor_team_ids TEXT NOT NULL DEFAULT '[]',
            allowed_ancestor_signing_ids TEXT NOT NULL DEFAULT '[]'
        )
    """)

    db.execute("""
        CREATE TABLE user_allowlist (
            id TEXT PRIMARY KEY,
            signing_id TEXT NOT NULL DEFAULT '',
            process_path TEXT NOT NULL DEFAULT '',
            platform_binary INTEGER NOT NULL DEFAULT 0,
            team_id TEXT NOT NULL DEFAULT ''
        )
    """)

    db.execute("""
        CREATE TABLE data_signatures (
            table_name TEXT PRIMARY KEY,
            signature BLOB NOT NULL
        )
    """)

    importUserRulesFromJSON(db)
    importUserAllowlistFromJSON(db)
}

// MARK: - Migration 002: Replace separate team/signing ID columns with combined signatures

private func migration002CombineSignatures(_ db: Database) {
    db.execute("""
        CREATE TABLE user_rules_new (
            id TEXT PRIMARY KEY,
            protected_path_prefix TEXT NOT NULL,
            allowed_process_paths TEXT NOT NULL DEFAULT '[]',
            allowed_signatures TEXT NOT NULL DEFAULT '[]',
            allowed_ancestor_process_paths TEXT NOT NULL DEFAULT '[]',
            allowed_ancestor_signatures TEXT NOT NULL DEFAULT '[]'
        )
    """)

    struct OldRule {
        let id: String
        let pathPrefix: String
        let processPaths: String
        let teamIDs: [String]
        let signingIDs: [String]
        let ancestorPaths: String
        let ancestorTeamIDs: [String]
        let ancestorSigningIDs: [String]
    }

    var oldRules: [OldRule] = []
    db.query("""
        SELECT id, protected_path_prefix,
               allowed_process_paths, allowed_team_ids, allowed_signing_ids,
               allowed_ancestor_process_paths, allowed_ancestor_team_ids, allowed_ancestor_signing_ids
        FROM user_rules
    """) { stmt in
        func col(_ i: Int32) -> String {
            guard let cStr = sqlite3_column_text(stmt, i) else { return "[]" }
            return String(cString: cStr)
        }
        oldRules.append(OldRule(
            id: col(0),
            pathPrefix: col(1),
            processPaths: col(2),
            teamIDs: decodeJSONStringArray(col(3)),
            signingIDs: decodeJSONStringArray(col(4)),
            ancestorPaths: col(5),
            ancestorTeamIDs: decodeJSONStringArray(col(6)),
            ancestorSigningIDs: decodeJSONStringArray(col(7))
        ))
    }

    for rule in oldRules {
        let sigs = crossProductSignatures(teamIDs: rule.teamIDs, signingIDs: rule.signingIDs)
        let ancestorSigs = crossProductSignatures(teamIDs: rule.ancestorTeamIDs, signingIDs: rule.ancestorSigningIDs)
        db.execute("""
            INSERT INTO user_rules_new
                (id, protected_path_prefix, allowed_process_paths, allowed_signatures,
                 allowed_ancestor_process_paths, allowed_ancestor_signatures)
            VALUES (?, ?, ?, ?, ?, ?)
        """, bindings: [
            .text(rule.id),
            .text(rule.pathPrefix),
            .text(rule.processPaths),
            .text(encodeJSONStringArray(sigs)),
            .text(rule.ancestorPaths),
            .text(encodeJSONStringArray(ancestorSigs)),
        ])
    }

    db.execute("DROP TABLE user_rules")
    db.execute("ALTER TABLE user_rules_new RENAME TO user_rules")
    db.execute("DELETE FROM data_signatures WHERE table_name = 'user_rules'")
    NSLog("Migration 002: Migrated %d rule(s) to combined signatures schema", oldRules.count)
}

private func crossProductSignatures(teamIDs: [String], signingIDs: [String]) -> [String] {
    guard !teamIDs.isEmpty else { return [] }
    guard !signingIDs.isEmpty else { return teamIDs.map { "\($0):*" } }
    return teamIDs.flatMap { teamID in signingIDs.map { "\(teamID):\($0)" } }
}

private func decodeJSONStringArray(_ json: String) -> [String] {
    (try? JSONDecoder().decode([String].self, from: Data(json.utf8))) ?? []
}

private func encodeJSONStringArray(_ array: [String]) -> String {
    guard let encoded = try? JSONEncoder().encode(array),
          let string = String(data: encoded, encoding: .utf8) else {
        fatalError("DatabaseMigrations: Failed to JSON-encode string array — [String] must always be encodable")
    }
    return string
}

// MARK: - JSON import helpers

private func importUserRulesFromJSON(_ db: Database) {
    let jsonURL = db.directory.appendingPathComponent("user-policy.json")
    let sigURL = db.directory.appendingPathComponent("user-policy.json.sig")

    guard let data = try? Data(contentsOf: jsonURL) else {
        NSLog("Migration 001: No user-policy.json found — starting fresh")
        return
    }

    if let sigData = try? Data(contentsOf: sigURL) {
        do {
            try PolicySigner.verify(data, signature: sigData)
        } catch {
            NSLog("Migration 001: user-policy.json signature FAILED — discarding")
            return
        }
    }

    guard let rules = try? JSONDecoder().decode([FAARule].self, from: data) else {
        NSLog("Migration 001: Failed to decode user-policy.json")
        return
    }

    db.saveUserRules(rules)
    NSLog("Migration 001: Imported %d user rule(s) from JSON", rules.count)
}

private func importUserAllowlistFromJSON(_ db: Database) {
    let jsonURL = db.directory.appendingPathComponent("global-allowlist.json")
    let sigURL = db.directory.appendingPathComponent("global-allowlist.json.sig")

    guard let data = try? Data(contentsOf: jsonURL) else {
        NSLog("Migration 001: No global-allowlist.json found — starting fresh")
        return
    }

    if let sigData = try? Data(contentsOf: sigURL) {
        do {
            try PolicySigner.verify(data, signature: sigData)
        } catch {
            NSLog("Migration 001: global-allowlist.json signature FAILED — discarding")
            return
        }
    }

    guard let entries = try? JSONDecoder().decode([AllowlistEntry].self, from: data) else {
        NSLog("Migration 001: Failed to decode global-allowlist.json")
        return
    }

    db.saveUserAllowlist(entries)
    NSLog("Migration 001: Imported %d user allowlist entry/entries from JSON", entries.count)
}
