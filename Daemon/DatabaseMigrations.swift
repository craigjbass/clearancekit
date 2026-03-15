//
//  DatabaseMigrations.swift
//  clearancekit-daemon
//
//  Schema migration definitions. Each migration runs exactly once, tracked by
//  the schema_migrations table. Add new migrations to the end of allMigrations.
//

import Foundation

// MARK: - Migration infrastructure

struct Migration {
    let version: Int
    let name: String
    let up: (Database) -> Void
}

let allMigrations: [Migration] = [
    Migration(version: 1, name: "Create tables and import from JSON", up: migration001CreateTablesAndImportJSON),
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
