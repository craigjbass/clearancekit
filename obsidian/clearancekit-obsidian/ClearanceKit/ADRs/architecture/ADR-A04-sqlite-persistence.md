---
id: ADR-A04
domain: architecture
date: 2026-03-15
status: Accepted
---
# ADR-A04: SQLite Persistence

## Context

Before commit `1a49d9c` (2026-03-15), policy rules and events were stored as signed JSON files on disk. JSON offered no query capability, no atomic multi-record updates, and every write required re-serialising the entire policy blob. As the data model grew (FAA rules, allowlist entries, jail rules, migration history), the file-per-collection approach became unwieldy.

## Options

1. **Keep JSON files** — no new dependencies; simple to read and write; but no transactions, no schema evolution path, and signing applies only to the whole blob (any partial write corrupts).
2. **SQLite via custom adapter** — SQL query capability; atomic transactions; SQLite3 is part of macOS (no additional dependency); schema evolution can be tracked in a migrations table.
3. **Core Data** — Apple-provided ORM on top of SQLite; adds a managed object context, change tracking, and SwiftUI integration. However, it imports AppKit/Foundation graph types that would leak into adapter boundaries, and its schema migration tooling is heavier than needed for a single-writer daemon.

## Decision

SQLite via a custom `Database` adapter with no ORM and no third-party dependencies. The implementation lives in `opfilter/Database/`:

- `Database.swift` — thin wrapper around `sqlite3_*` C APIs; opens the database at `/Library/Application Support/clearancekit/store.db`; all reads and writes go through this type.
- `DatabaseMigrations.swift` — versioned migrations tracked in a `schema_migrations` table; migrations run sequentially at startup; migration 001 created the initial schema and imported existing JSON data; migration 002 introduced the `ProcessSignature` combined format; migration 004 added `user_jail_rules`.

After every write, `PolicySigner` signs the database file with EC-P256 and stores the signature alongside it. On load, the signature is verified before any data is trusted. The database directory is owned by root with `0o700` permissions and the file has `0o600` permissions; the GUI app cannot read or write it directly.

WAL mode was not enabled: opfilter is the single writer, so the default journal mode is sufficient.

## Consequences

- Zero third-party Swift package dependencies; `sqlite3` is available on every macOS version ClearanceKit targets.
- The migrations table gives a clear, auditable path for schema evolution without data loss.
- ECDSA signing detects any out-of-band tampering with the database file, complementing the filesystem ACL.
- Because there is only one writer (opfilter), no connection pooling or WAL coordination is needed.
- The `Database` adapter is the only code that issues SQL; domain types (`FAARule`, `JailRule`, `ProcessSignature`) are passed in and out as Swift values, keeping SQL out of the domain layer.
