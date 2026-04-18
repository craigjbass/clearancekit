# ClearanceKit ADRs and Obsidian Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Process 621 commits of ClearanceKit history and produce ~30 ADRs plus architecture overview, component notes, and glossary in the Obsidian vault.

**Architecture:** 6 tasks — 1 setup task followed by 5 parallel agents (architecture, security, features, operations, overview+components+glossary). Each agent reads relevant commits and source files, then writes Markdown files to Obsidian via MCP tools.

**Tech Stack:** Git CLI, obsidian-mcp-tools MCP server, Swift source files in repo.

---

## Key Constants

- **Vault path:** Files are created relative to the vault root. Do NOT include the absolute path in `path` parameters — Obsidian MCP paths are vault-relative.
- **Repo root:** `/Users/craigjbass/Projects/clearancekit/`
- **MCP tool for creating files:** `mcp__obsidian-mcp-tools__create_vault_file` (load schema via ToolSearch first)
- **MCP tool for reading files:** `mcp__obsidian-mcp-tools__get_vault_file`

## ADR Template (use for every ADR)

```markdown
---
id: ADR-NNN
domain: <architecture|security|features|operations>
date: YYYY-MM-DD
status: Accepted
---
# ADR-NNN: <Title>

## Context

<What situation existed before this decision? What problem or requirement drove it?>

## Options

<What alternatives were considered? List 2-3 with brief trade-off notes.>

## Decision

<What was chosen? One paragraph on what was implemented and why it was preferred.>

## Consequences

<What constraints, follow-on work, or trade-offs does this introduce? Both positive and negative.>
```

---

## Task 1: Create Obsidian folder structure

**Files to create (empty placeholders — agents will populate):**
- `ClearanceKit/Architecture Overview.md`
- `ClearanceKit/Glossary.md`
- `ClearanceKit/Components/opfilter.md`
- `ClearanceKit/Components/clearancekit-gui.md`
- `ClearanceKit/Components/xpc-layer.md`
- `ClearanceKit/Components/policy-engine.md`
- `ClearanceKit/Components/process-tree.md`
- `ClearanceKit/ADRs/architecture/.keep`
- `ClearanceKit/ADRs/security/.keep`
- `ClearanceKit/ADRs/features/.keep`
- `ClearanceKit/ADRs/operations/.keep`

- [ ] **Step 1: Load MCP tool schema**

Run in Claude Code: use ToolSearch with `query: "select:mcp__obsidian-mcp-tools__create_vault_file,mcp__obsidian-mcp-tools__list_vault_files"` to load the schemas.

- [ ] **Step 2: Create top-level placeholder files**

Use `mcp__obsidian-mcp-tools__create_vault_file` to create each of the 11 paths above with content `# (to be populated)`. This creates the folder structure implicitly (Obsidian creates parent folders on file creation).

- [ ] **Step 3: Verify structure**

Use `mcp__obsidian-mcp-tools__list_vault_files` to confirm folders exist.

---

## Task 2: Architecture ADRs

**Run in parallel with Tasks 3, 4, 5, 6.**

Write 8 ADRs covering structural decisions: hexagonal architecture, process boundaries, IPC, persistence, identity model, pipeline design, and protocol placement.

**Files to create:**
- `ClearanceKit/ADRs/architecture/ADR-A01-hexagonal-architecture.md`
- `ClearanceKit/ADRs/architecture/ADR-A02-daemon-gui-separation.md`
- `ClearanceKit/ADRs/architecture/ADR-A03-xpc-ipc-boundary.md`
- `ClearanceKit/ADRs/architecture/ADR-A04-sqlite-persistence.md`
- `ClearanceKit/ADRs/architecture/ADR-A05-process-signature-identity.md`
- `ClearanceKit/ADRs/architecture/ADR-A06-dual-es-client.md`
- `ClearanceKit/ADRs/architecture/ADR-A07-two-stage-file-auth-pipeline.md`
- `ClearanceKit/ADRs/architecture/ADR-A08-protocol-placement.md`

**Research commands (run these before writing each ADR):**

```bash
# ADR-A01: Hexagonal architecture
git show 9074ce8
git show 281fdda  # opfilter subdirectory reorganisation
git show 162979e  # CLAUDE.md rewrite documenting hexagonal arch

# ADR-A02: Daemon/GUI separation
git show fe28ccc  # Introduce daemon
git show 5a88795  # Merge daemon into opfilter as single privileged process
git show e71379d  # Move policy storage to daemon
git show c525c98  # Move process enumeration from GUI to daemon

# ADR-A03: XPC IPC boundary
git show 31c617c  # Deliver FAA policy dynamically via daemon XPC
git show 7b23e09  # Secure XPC server v2
git show fe044c0  # Refactor XPCServer: extract PolicyRepository + EventBroadcaster
git show 0a997cd  # Wire ConnectionValidator into XPC listener

# ADR-A04: SQLite persistence
git show 1a49d9c  # Migrate daemon persistence from JSON files to SQLite

# ADR-A05: ProcessSignature identity model
git show 4d8bb89  # Consolidate team ID and signing ID into ProcessSignature pairs
git show 91a438c  # Introduce apple team ID sentinel
git show b04d0a3  # Normalise empty team ID to 'apple'
git show 1bf97be  # Evaluate teamID+signingID as AND not OR

# ADR-A06: Dual ES client (FAA + Jail)
git show 9af5bb4  # Add App Jail domain types and FilterInteractor integration
git show 540674b  # Split FilterInteractor into FAAFilterInteractor and JailFilterInteractor
git show 7768ef9  # Switch AUTH_EXEC to NOTIFY_EXEC

# ADR-A07: Two-stage file-auth pipeline
git show edd6101  # Replace unbounded Task dispatch with 2-stage file-auth pipeline
git show 614a794  # Move FileAuthPipeline construction to main.swift
git show eeb0ebc  # Add dedicated postRespondQueue

# ADR-A08: Protocol placement convention
git show 2f7ba60  # Relocate protocols to live with their consumers
git show ff065b5  # Add protocol placement rule to CLAUDE.md
```

**Source files to read:**
```bash
cat /Users/craigjbass/Projects/clearancekit/CLAUDE.md
ls /Users/craigjbass/Projects/clearancekit/opfilter/
ls /Users/craigjbass/Projects/clearancekit/Shared/
cat /Users/craigjbass/Projects/clearancekit/opfilter/Filter/FilterInteractor.swift 2>/dev/null | head -80
cat /Users/craigjbass/Projects/clearancekit/opfilter/XPC/XPCServer.swift 2>/dev/null | head -80
```

- [ ] **Step 1: Research ADR-A01 (Hexagonal Architecture)**

Run the git show commands for ADR-A01 above. Read CLAUDE.md Architecture section. Note: hexagonal arch was introduced in commit `9074ce8` (2026-03-07), formally documented in CLAUDE.md rewrite `162979e` (2026-03-20), and opfilter was reorganised into subdirectories in `281fdda` (2026-03-21).

- [ ] **Step 2: Write ADR-A01 to Obsidian**

Use `mcp__obsidian-mcp-tools__create_vault_file` with path `ClearanceKit/ADRs/architecture/ADR-A01-hexagonal-architecture.md`. Content must follow the ADR template. Key points:
- Context: opfilter was a monolithic file mixing ES event handling, policy logic, and logging
- Options: (1) layered architecture, (2) hexagonal/ports-and-adapters, (3) keep monolith
- Decision: hexagonal with Domain (Shared/), Ports (protocols), Adapters (opfilter/ subdirs)
- Consequences: domain code never imports EndpointSecurity/AppKit/SQLite; adapters own those imports; enables unit testing domain logic without OS dependencies

- [ ] **Step 3: Research ADR-A02 (Daemon/GUI separation)**

Run git show commands for ADR-A02. Key insight: a daemon was first introduced as a separate process (`fe28ccc`), then merged back into opfilter (`5a88795`), but policy storage was moved from GUI to daemon (`e71379d`) and process enumeration moved from GUI to daemon (`c525c98`). The "daemon" label now refers to the XPC-connected opfilter process.

- [ ] **Step 4: Write ADR-A02 to Obsidian**

Path: `ClearanceKit/ADRs/architecture/ADR-A02-daemon-gui-separation.md`. Key points:
- Context: GUI app needed policy enforcement (ES kernel extension work) but macOS doesn't allow GUI apps to hold System Extension
- Options: (1) all in one process, (2) separate daemon process, (3) opfilter system extension + GUI connected via XPC
- Decision: opfilter system extension holds ES client and all privileged work; GUI communicates via XPC; policy storage lives in opfilter to enforce access
- Consequences: policy mutation requires XPC round-trip; opfilter self-protects its own database via FAA rule

- [ ] **Step 5: Research and write ADR-A03 (XPC IPC boundary)**

Run git show commands for ADR-A03. Write to `ClearanceKit/ADRs/architecture/ADR-A03-xpc-ipc-boundary.md`. Key points:
- Context: GUI and opfilter run as separate processes and need to share policy and events
- Options: (1) Unix domain socket, (2) Mach ports directly, (3) NSXPCConnection with audit token validation
- Decision: NSXPCConnection with `ConnectionValidator` using audit tokens to verify client identity on every message
- Consequences: XPC protocol defined in `Shared/XPCProtocol.swift` (compiled into both binaries); `ConnectionValidator` checks team ID and signing ID of connecting process

- [ ] **Step 6: Research and write ADR-A04 (SQLite persistence)**

Run git show `1a49d9c`. Write to `ClearanceKit/ADRs/architecture/ADR-A04-sqlite-persistence.md`. Key points:
- Context: policy rules and events were stored as JSON files on disk
- Options: (1) keep JSON files, (2) SQLite with WAL mode, (3) Core Data
- Decision: SQLite via custom `Database` adapter (no ORM, no third-party deps); signed with EC-P256 to detect tampering
- Consequences: zero third-party dependencies maintained; migration system in `DatabaseMigrations.swift`; database ACL restricted to opfilter executable only

- [ ] **Step 7: Research and write ADR-A05 (ProcessSignature identity)**

Run git show commands for ADR-A05. Write to `ClearanceKit/ADRs/architecture/ADR-A05-process-signature-identity.md`. Key points:
- Context: processes were identified by team ID OR signing ID separately, causing AND/OR confusion
- Options: (1) keep separate fields, (2) require both always, (3) pair (teamID, signingID) as composite identity
- Decision: `ProcessSignature` struct pairs teamID+signingID; policy evaluation treats them as AND; Apple binaries normalised to teamID="apple"
- Consequences: wildcard `*` supported per field; `*:*` matches any process; "apple" sentinel avoids empty-string special-casing

- [ ] **Step 8: Research and write ADR-A06 (Dual ES client)**

Run git show commands for ADR-A06. Write to `ClearanceKit/ADRs/architecture/ADR-A06-dual-es-client.md`. Key points:
- Context: file-access authorisation (FAA) and app jail (process containment) have different ES event sets and latency requirements
- Options: (1) one ES client handling all events, (2) separate ES clients per concern
- Decision: `ESInboundAdapter` (FAA) and `ESJailAdapter` (jail) as separate adapters with separate ES clients; jail toggleable at runtime
- Consequences: AUTH_EXEC switched from AUTH to NOTIFY on FAA path to remove latency; jail AUTH events responded synchronously to avoid deadline misses

- [ ] **Step 9: Research and write ADR-A07 (Two-stage pipeline)**

Run git show commands for ADR-A07. Write to `ClearanceKit/ADRs/architecture/ADR-A07-two-stage-file-auth-pipeline.md`. Key points:
- Context: unbounded `Task {}` dispatch from ES callback caused thread starvation under load; ES AUTH events have a hard deadline (default ~15ms on macOS)
- Options: (1) keep unbounded tasks, (2) bounded actor, (3) explicit two-stage pipeline with dedicated queues
- Decision: Stage 1 runs on ES callback thread (fast path: cache lookup, global allowlist check); Stage 2 runs on `postRespondQueue` (slow path: audit logging, XPC broadcast). All queues use `.never` autorelease frequency.
- Consequences: ES respond call always happens on Stage 1 before any slow work; correlation UUID threads through both stages for debugging

- [ ] **Step 10: Research and write ADR-A08 (Protocol placement)**

Run git show commands for ADR-A08. Write to `ClearanceKit/ADRs/architecture/ADR-A08-protocol-placement.md`. Key points:
- Context: protocols were placed near their implementations, causing inverted dependency arrows (implementations in Shared/ "knew about" consumers in adapters)
- Options: (1) protocols near implementors, (2) protocols in Shared/ always, (3) protocols near consumers
- Decision: protocol lives in the same folder as the type that takes it as a constructor parameter (the consumer defines what it needs); exception: protocols used by both binary targets live in Shared/
- Consequences: dependency arrow always points inward (consumer → protocol ← implementor); conformances declared in adapter files to keep Shared/ free

---

## Task 3: Security ADRs

**Run in parallel with Tasks 2, 4, 5, 6.**

Write 6 ADRs covering security boundaries, signing, authentication, and tamper resistance.

**Files to create:**
- `ClearanceKit/ADRs/security/ADR-S01-ec-p256-policy-signing.md`
- `ClearanceKit/ADRs/security/ADR-S02-touch-id-policy-mutations.md`
- `ClearanceKit/ADRs/security/ADR-S03-xpc-audit-token-validation.md`
- `ClearanceKit/ADRs/security/ADR-S04-policy-database-acl.md`
- `ClearanceKit/ADRs/security/ADR-S05-tamper-resistance-adapter.md`
- `ClearanceKit/ADRs/security/ADR-S06-opfilter-self-protection.md`

**Research commands:**

```bash
# ADR-S01: EC-P256 policy signing
git show 4bb6687   # Sign on-disk policy with EC-P256 key in System Keychain
git show 0216b95   # Lock down policy signing key ACL and enable Secure Enclave
git show 67146dd   # Rewrite PolicySigner to use data-protection keychain
git show fb6a539   # Document PolicySigner requirements and SE infeasibility
git show a7a3dde   # Fix: reject tampered data when signature row is missing

# ADR-S02: Touch ID
git show e43a3a2   # Require Touch ID for all policy mutations
git show e713646   # Implement policy export and import with Touch ID protection
git show ca54899   # Prompt user to resolve database signature issues with Touch ID

# ADR-S03: XPC audit token validation
git show 7b23e09   # Secure XPC server v2 with audit_token-based validation
git show 0a997cd   # Wire ConnectionValidator into XPC listener
git show 6233b33   # Start XPC server before process-tree scan (latency)

# ADR-S04: Policy database ACL
git show e71379d   # Move policy storage to daemon; protect with FAA rule and filesystem permissions
git show 6cdf14c   # Lock software key ACL to daemon executable only
git show 4b89e18   # Migrate existing System Keychain key ACL to daemon-only on load

# ADR-S05: Tamper resistance adapter
git show fb88dce   # Add ESTamperResistanceAdapter to block process suspension and signal attacks
git show d6a765c   # Wire tamper DENY events to GUI via XPC

# ADR-S06: opfilter self-protection
git show 8386ae0   # Tighten opfilter self-protection to exact signing ID
git show e71379d   # Move policy storage to daemon (includes FAA rule protecting DB)
```

**Source files to read:**
```bash
ls /Users/craigjbass/Projects/clearancekit/opfilter/Policy/
cat /Users/craigjbass/Projects/clearancekit/SECURITY.md
```

- [ ] **Step 1: Research and write ADR-S01 (EC-P256 policy signing)**

Run git show commands for ADR-S01. Read `opfilter/Policy/PolicySigner.swift`. Write to `ClearanceKit/ADRs/security/ADR-S01-ec-p256-policy-signing.md`. Key points:
- Context: policy database stored on disk is readable by root; tampering could whitelist malicious processes
- Options: (1) no signing, (2) HMAC with symmetric key, (3) EC-P256 asymmetric signing in System Keychain
- Decision: EC-P256 key stored in System Keychain (data-protection class), signing ID restricted to opfilter executable ACL; attempted Secure Enclave but Touch ID requirement made it infeasible for background daemon
- Consequences: `PolicySigner` signs after every write; `Database` verifies signature on open; tampered or missing signature triggers Touch ID re-authorisation prompt; key ACL migrated from old format on first load

- [ ] **Step 2: Research and write ADR-S02 (Touch ID)**

Write to `ClearanceKit/ADRs/security/ADR-S02-touch-id-policy-mutations.md`. Key points:
- Context: policy rules control what processes can access what files; compromised GUI could add whitelist rules silently
- Options: (1) no auth gate, (2) password confirmation, (3) Touch ID / deviceOwnerAuthentication via LAContext
- Decision: Touch ID required for all policy mutations (add, edit, delete rules), policy export/import, and signature repair; uses `deviceOwnerAuthentication` to fall back to password when Touch ID unavailable
- Consequences: mutations require user presence; background policy updates (MDM managed profile) bypass Touch ID as they come from a separate privileged channel

- [ ] **Step 3: Research and write ADR-S03 (XPC audit token validation)**

Write to `ClearanceKit/ADRs/security/ADR-S03-xpc-audit-token-validation.md`. Key points:
- Context: NSXPCConnection PID-based checks are vulnerable to PID reuse attacks
- Options: (1) PID check, (2) entitlement check, (3) audit token with code signing verification
- Decision: `ConnectionValidator` reads `auditToken` from each incoming connection and verifies team ID + signing ID via SecCode API; `get-task-allow` removed from GUI entitlements
- Consequences: only the exact signed GUI binary can connect to opfilter; XPC server started before process-tree scan to reduce connection latency at launch

- [ ] **Step 4: Research and write ADR-S04 (Policy database ACL)**

Write to `ClearanceKit/ADRs/security/ADR-S04-policy-database-acl.md`. Key points:
- Context: SQLite database on disk could be modified by any process running as the same user
- Options: (1) rely on filesystem permissions only, (2) add a FAA self-protection rule, (3) ACL on signing key + FAA rule + filesystem permissions
- Decision: three-layer defence: (a) filesystem permissions set to opfilter-only, (b) FAA rule in opfilter protecting its own database path, (c) signing key ACL restricted to opfilter executable hash
- Consequences: GUI cannot directly write policy database; all mutations go through XPC; ACL migrated on first load

- [ ] **Step 5: Research and write ADR-S05 (Tamper resistance adapter)**

Write to `ClearanceKit/ADRs/security/ADR-S05-tamper-resistance-adapter.md`. Key points:
- Context: a privileged attacker could suspend opfilter (SIGSTOP) or send SIGKILL to bypass file access controls temporarily
- Options: (1) no protection, (2) watchdog process, (3) ESTamperResistanceAdapter subscribing to ES process events
- Decision: `ESTamperResistanceAdapter` subscribes to ES SIGNAL and PROC_SUSPEND_RESUME events targeting opfilter's own PID; denies SIGSTOP/SIGKILL via AUTH response; broadcasts DENY events to GUI via XPC
- Consequences: protects against process suspension attacks; GUI shows tamper events in the event list

- [ ] **Step 6: Research and write ADR-S06 (opfilter self-protection)**

Write to `ClearanceKit/ADRs/security/ADR-S06-opfilter-self-protection.md`. Key points:
- Context: opfilter's own binary and database could be replaced or modified while running
- Options: (1) no self-protection, (2) integrity check on startup only, (3) FAA rule protecting opfilter paths
- Decision: opfilter adds a FAA rule protecting its own binary path, database path, and configuration; rule keyed to exact signing ID of opfilter itself; tightened from team-ID-only to exact signing ID
- Consequences: any process attempting to write to opfilter paths is denied by opfilter itself; creates a self-referential protection loop

---

## Task 4: Features ADRs

**Run in parallel with Tasks 2, 3, 5, 6.**

Write 10 ADRs covering feature design decisions.

**Files to create:**
- `ClearanceKit/ADRs/features/ADR-F01-process-ancestry-tracking.md`
- `ClearanceKit/ADRs/features/ADR-F02-global-allowlist.md`
- `ClearanceKit/ADRs/features/ADR-F03-managed-policy-tier.md`
- `ClearanceKit/ADRs/features/ADR-F04-preset-system.md`
- `ClearanceKit/ADRs/features/ADR-F05-write-only-rules.md`
- `ClearanceKit/ADRs/features/ADR-F06-app-jail.md`
- `ClearanceKit/ADRs/features/ADR-F07-wildcard-matching.md`
- `ClearanceKit/ADRs/features/ADR-F08-es-response-caching.md`
- `ClearanceKit/ADRs/features/ADR-F09-preset-drift-detection.md`
- `ClearanceKit/ADRs/features/ADR-F10-mcp-server-research-tool.md`

**Research commands:**

```bash
# ADR-F01: Process ancestry
git show 81a5bea   # Add process ancestry checks with audit tokens and codesigning
git show 68e91e9   # Track process ancestry via FORK/EXEC/EXIT events and initial scan
git show 9bb62a6   # Replace PID-based ProcessTree with audit-token ProcessIdentity
git show a9916dd   # Defer ancestry lookup until actually needed in checkFAAPolicy
git show 39258c3   # Add global allow list ancestry rules support

# ADR-F02: Global allowlist
git show 9497550   # Add global allowlist that bypasses all FAA policy rules
git show 59d40fd   # Support wildcard signing ID in global allowlist entries
git show 588b801   # Unify allowlist and policy evaluation under evaluateAccess

# ADR-F03: Managed policy tier
git show c12064e   # Add managed profile policy tier between baseline and user rules
git show facd3bb   # Ensure MDM policy flow is appropriate and document
git show 8806b62   # Add MDM jail config via JailRules preference key

# ADR-F04: Preset system
git show 391f101   # Add App Protections tab with built-in Safari data protection preset
git show d16fc3e   # Add preset drift detection with per-row and bulk update actions
git show 9f11338   # Split builtInPresets into individual files under clearancekit/Presets/
git show b39d99a   # Sync presets with exported policy

# ADR-F05: Write-only rules
git show 890a08d   # Add AccessKind enum and open-flag classifier
git show bdb4c7b   # Thread accessKind from ES events into FileAuthEvent
git show 835dc2c   # Add enforceOnWriteOnly to FAARule
git show f7f4713   # Skip write-only rules on read events
git show bd916e9   # Pin cache safety for write-only rules

# ADR-F06: App Jail
git show 9af5bb4   # Add App Jail domain types, policy evaluation, FilterInteractor integration
git show d068148   # Implement ESJailAdapter
git show 844141b   # Change jail allowed-path model to require explicit wildcards
git show 844061b   # Fix: respond to jail AUTH events synchronously

# ADR-F07: Wildcard matching
git show b212a57   # Add wildcard support to protected path patterns
git show 2482275   # Support universal wildcard *:* in ProcessSignature matching
git show d1798c4   # Evaluate rules by most-specific path, not array order

# ADR-F08: ES response caching
git show 51fce76   # Cache ES allow results to skip redundant policy evaluation
git show b6b71f7   # Implement ES response caching via CacheDecisionProcessor
git show 2cebd4f   # Send cache=true for all isGloballyAllowed events
git show bd916e9   # Pin cache safety for write-only rules in pipeline

# ADR-F09: Preset drift detection
git show d16fc3e   # Add preset drift detection with per-row and bulk update actions

# ADR-F10: MCP server for research
git show db4b341   # Add MCP server for app protections research workflow
git show 9096289   # Add MCP server feature flag with tamper-resistant signature
git show c6cff32   # Expose enforce_on_write_only via MCP add_rule and update_rule
```

- [ ] **Step 1: Research and write ADR-F01 (Process ancestry tracking)**

Write to `ClearanceKit/ADRs/features/ADR-F01-process-ancestry-tracking.md`. Key points:
- Context: knowing which process opened a file is insufficient for security policy — a compromised child of a trusted parent should be treated differently
- Options: (1) no ancestry, (2) single-parent check, (3) full ancestry chain via FORK/EXEC/EXIT tracking
- Decision: `ProcessTree` tracks ancestry via FORK/EXEC/EXIT ES events plus initial scan; uses audit tokens (not PIDs) to prevent PID reuse attacks; `ProcessTreeProtocol` enables lazy lookup via `@Sendable () async -> [AncestorInfo]` closures
- Consequences: ancestry lookups deferred until a rule actually requires them (performance); ancestry CPU cost documented as warning to users; `ProcessTree` moved to `Shared/` for dual-binary compilation

- [ ] **Step 2: Research and write ADR-F02 (Global allowlist)**

Write to `ClearanceKit/ADRs/features/ADR-F02-global-allowlist.md`. Key points:
- Context: many Apple system processes legitimately access all files; building per-process FAA rules for each is impractical
- Options: (1) per-process rules for every system binary, (2) global skip list evaluated before FAA policy, (3) separate allowlist tier
- Decision: `GlobalAllowlist` evaluated before FAA rules; matches on (teamID, signingID) pairs or (teamID, *) wildcards; XProtect bundle enumerated at launch and on XProtect updates to populate
- Consequences: allowlist bypass means no event logged; wildcard signingID added for Apple processes that vary; baseline auto-resyncs when XProtect bundle changes

- [ ] **Step 3: Research and write ADR-F03 (Managed policy tier)**

Write to `ClearanceKit/ADRs/features/ADR-F03-managed-policy-tier.md`. Key points:
- Context: enterprises need to deploy policy via MDM that users cannot override but that sits above the built-in baseline
- Options: (1) embed MDM rules in baseline, (2) separate managed tier evaluated between baseline and user rules, (3) MDM replaces user rules entirely
- Decision: three-tier evaluation: baseline → managed (MDM profile) → user rules; managed rules loaded from macOS preference key via `ManagedPolicyLoader` and `ManagedAllowlistLoader`; GUI shows managed rules as read-only
- Consequences: MDM admin can lock down policy without overwriting user customisations; managed rules cannot be edited via Touch ID flow; ancestor allowlist also configurable via MDM

- [ ] **Step 4: Research and write ADR-F04 (Preset system)**

Write to `ClearanceKit/ADRs/features/ADR-F04-preset-system.md`. Key points:
- Context: users need a starting point for common apps (Safari, Mail, Chrome, etc.) rather than building rules from scratch via event discovery
- Options: (1) no presets, (2) hardcoded bundled rules, (3) preset structs with drift detection
- Decision: `AppPreset` structs with stable UUIDs per rule (UUIDs generated via `uuidgen`, never hand-crafted); presets appear as non-editable policy entries; drift detection compares installed preset rules to current built-in version and offers bulk update
- Consequences: preset UUIDs must never change post-ship (database signing uses them as keys); new process IDs can be added to existing preset rules; `builtInPresets` split into per-app files under `clearancekit/Presets/`

- [ ] **Step 5: Research and write ADR-F05 (Write-only rules)**

Write to `ClearanceKit/ADRs/features/ADR-F05-write-only-rules.md`. Key points:
- Context: some legitimate processes need read access to protected paths (e.g., Time Machine backing up) but write access is the security concern
- Options: (1) deny all access, (2) separate read/write rules, (3) `enforceOnWriteOnly` flag on existing rules
- Decision: `AccessKind` enum (read/write) derived from ES open flags; `enforceOnWriteOnly` field on `FAARule`; pipeline skips write-only rules on read events; cache invalidated on write-only rules (cache would return allow for reads, poisoning write checks)
- Consequences: Santa export maps `enforceOnWriteOnly` to `AllowReadAccess`; MDM plist and mobileconfig export include the flag; write-only rules must not be cached (pin enforced in pipeline)

- [ ] **Step 6: Research and write ADR-F06 (App Jail)**

Write to `ClearanceKit/ADRs/features/ADR-F06-app-jail.md`. Key points:
- Context: FAA rules control which processes can access which paths, but don't contain processes to allowed paths only — a jailed app might write to arbitrary locations
- Options: (1) no containment, (2) sandbox profiles, (3) per-app jail rules via second ES client
- Decision: `ESJailAdapter` with separate ES client subscribing to AUTH_OPEN for jailed processes; allowed paths require explicit wildcards (no implicit subdirectory access); jail enforcement propagates to child processes via FORK/EXEC ancestry; jail feature opt-in via XPC toggle
- Consequences: jail AUTH events responded synchronously (deadline risk on async path); background sweep detects jailed processes that started before opfilter; jail events shown in separate process tree view; jailed process tracking uses (pid, pidVersion) to prevent PID reuse

- [ ] **Step 7: Research and write ADR-F07 (Wildcard matching)**

Write to `ClearanceKit/ADRs/features/ADR-F07-wildcard-matching.md`. Key points:
- Context: exact path matching is too brittle (versioned app bundles, user home directory variations)
- Options: (1) exact match only, (2) prefix matching, (3) glob patterns
- Decision: glob(3)-compatible path patterns via Santa path conversion; `*` within-component wildcard; `**` cross-component wildcard; `*:*` universal ProcessSignature match; most-specific path wins (not array order)
- Consequences: paths exported to Santa converted via `santaPath`; rule evaluation order changed from array-order to specificity-order (`d1798c4`)

- [ ] **Step 8: Research and write ADR-F08 (ES response caching)**

Write to `ClearanceKit/ADRs/features/ADR-F08-es-response-caching.md`. Key points:
- Context: ES AUTH_OPEN fires for every file access; repeated policy evaluation for the same process/path pair wastes CPU cycles
- Options: (1) no caching, (2) in-process LRU cache, (3) ES kernel-level cache via `cache` parameter on respond
- Decision: pass `cache: true` to ES respond for allow decisions; ES kernel caches the result and skips future callbacks for same (process, path) pair; cache invalidated on policy change via `es_clear_cache`; write-only rules must not be cached (read accesses would incorrectly skip the rule)
- Consequences: dramatic reduction in opfilter CPU on repeated file accesses; `es_clear_cache` called once at startup after ES client setup; cache invalidated on every policy update XPC message

- [ ] **Step 9: Research and write ADR-F09 (Preset drift detection)**

Write to `ClearanceKit/ADRs/features/ADR-F09-preset-drift-detection.md`. Key points:
- Context: app updates add new process signing IDs to existing presets; users with old installed presets would miss coverage
- Options: (1) no detection (user must manually update), (2) automatic silent update, (3) per-row drift badge with bulk update action
- Decision: compare each installed preset rule's current process list to the built-in definition; show drift badge on rows where preset has new content; offer per-row and bulk update actions
- Consequences: preset rule UUIDs must be stable (drift detection keyed by UUID); user controls when to apply updates; preset updates require Touch ID

- [ ] **Step 10: Research and write ADR-F10 (MCP server)**

Write to `ClearanceKit/ADRs/features/ADR-F10-mcp-server-research-tool.md`. Key points:
- Context: building app protection presets required manually inspecting process ancestry for many macOS apps — slow and error-prone
- Options: (1) manual process inspection, (2) custom CLI tool, (3) embedded MCP server exposing policy data to AI assistants
- Decision: embedded MCP server in opfilter exposing `list_events`, `add_rule`, `update_rule` tools; gated behind tamper-resistant feature flag; used during development workflow to discover process signing IDs
- Consequences: MCP server is an opt-in development/research tool; feature flag signed to prevent tampering; `enforce_on_write_only` exposed via MCP for write-only rule creation

---

## Task 5: Operations ADRs

**Run in parallel with Tasks 2, 3, 4, 6.**

Write 9 ADRs covering CI/CD, supply chain security, and release engineering.

**Files to create:**
- `ClearanceKit/ADRs/operations/ADR-O01-github-actions-release.md`
- `ClearanceKit/ADRs/operations/ADR-O02-slsa-l3-provenance.md`
- `ClearanceKit/ADRs/operations/ADR-O03-actions-sha-pinning.md`
- `ClearanceKit/ADRs/operations/ADR-O04-sonarcloud-analysis.md`
- `ClearanceKit/ADRs/operations/ADR-O05-codeql-swift-analysis.md`
- `ClearanceKit/ADRs/operations/ADR-O06-dependabot-supply-chain.md`
- `ClearanceKit/ADRs/operations/ADR-O07-openssf-scorecard.md`
- `ClearanceKit/ADRs/operations/ADR-O08-prerelease-versioning.md`
- `ClearanceKit/ADRs/operations/ADR-O09-zero-third-party-deps.md`

**Research commands:**

```bash
# ADR-O01: GitHub Actions release
git show e28edae   # Add GitHub Actions release workflow with notarization and attestation
git show 3c8cd02   # Publish release assets in a single atomic job
git show 243623e   # Prevent script injection via tag name in release workflow
git show dd6bc64   # Declare top-level least-privilege permissions in release workflows

# ADR-O02: SLSA L3
git show d769c30   # Add SLSA L3 provenance and Sigstore bundle to release assets
git show e353aa8   # Pin SLSA generator by SHA with compile-generator: true
git show 3d9dfd5   # Grant contents: write to SLSA provenance caller job

# ADR-O03: SHA pinning
git show 73a4f68   # Pin GitHub Actions by commit SHA and hash-pin pip Pillow
git show 2441e70   # Pin actions in CodeQL workflow by commit SHA

# ADR-O04: SonarCloud
git show 3005356   # Configure SonarCloud analysis for the project
git show 3b9b55d   # Exclude test code from SonarCloud duplication check
git show 2ab3798   # Delete old sonarcloud workflow (replaced)

# ADR-O05: CodeQL
git show ca0cb45   # Add CodeQL analysis workflow configuration
git show 053aa03   # Run Swift CodeQL analysis on macos-26 with Xcode 26
git show d203f0e   # Switch Swift CodeQL to buildless extraction

# ADR-O06: Dependabot
git show 89dfe46   # Add Dependabot config for GitHub Actions and pip

# ADR-O07: OpenSSF Scorecard
git show 331cf56   # Add Scorecard workflow for supply-chain security
git show 42f1098   # Add OpenSSF Scorecard assessment

# ADR-O08: Prerelease versioning
git show 7560b10   # ci: add prerelease workflow for commits to main
git show 50e449e   # Fix prerelease version numbering to base on last stable release
git show ff28410   # Explicitly filter out -beta- tags when computing next version increment

# ADR-O09: Zero deps (evidence from README and commit history)
git log --oneline --grep="third-party" | head -5
git log --oneline --grep="dependency" | head -5
git show 5bf2cd4   # Highlight zero third-party dependencies in README
```

- [ ] **Step 1: Research and write ADR-O01 (GitHub Actions release)**

Write to `ClearanceKit/ADRs/operations/ADR-O01-github-actions-release.md`. Key points:
- Context: manual release process (DMG creation, notarization, upload) is error-prone and hard to audit
- Options: (1) manual releases, (2) Fastlane, (3) GitHub Actions with xcodebuild + notarytool
- Decision: GitHub Actions workflow using `xcodebuild archive`, `xcodebuild -exportArchive`, Apple notarization via `notarytool`, DMG creation; assets published in single atomic job; least-privilege permissions declared top-level; script injection prevented by quoting tag name references
- Consequences: immutable releases created by CI only (CLAUDE.md forbids manual release creation); release notes editable post-creation; provenance attestation attached

- [ ] **Step 2: Research and write ADR-O02 (SLSA L3 provenance)**

Write to `ClearanceKit/ADRs/operations/ADR-O02-slsa-l3-provenance.md`. Key points:
- Context: users downloading release binaries cannot verify the binary was produced from the published source code
- Options: (1) no provenance, (2) build attestation only, (3) SLSA L3 provenance + Sigstore bundle
- Decision: SLSA Level 3 provenance via `slsa-framework/slsa-github-generator`; Sigstore bundle attached to every release; generator pinned by SHA with `compile-generator: true`
- Consequences: users can verify build provenance via `slsa-verifier`; Sigstore bundle enables transparency log verification; `contents: write` permission required on caller job

- [ ] **Step 3: Research and write ADR-O03 (GitHub Actions SHA pinning)**

Write to `ClearanceKit/ADRs/operations/ADR-O03-actions-sha-pinning.md`. Key points:
- Context: GitHub Actions version tags (`@v3`) are mutable and can be hijacked in supply chain attacks
- Options: (1) use version tags, (2) use branch names, (3) pin every action by full commit SHA
- Decision: all GitHub Actions pinned by full 40-character commit SHA; pip dependencies hash-pinned via `--require-hashes`; Dependabot configured to keep SHA pins updated
- Consequences: immune to tag hijack attacks; Dependabot automation required to keep pins current; SHA comments added alongside each pin for readability

- [ ] **Step 4: Research and write ADR-O04 (SonarCloud)**

Write to `ClearanceKit/ADRs/operations/ADR-O04-sonarcloud-analysis.md`. Key points:
- Context: code quality and security vulnerability detection in Swift required automated tooling
- Options: (1) no static analysis, (2) SwiftLint only, (3) SonarCloud with build wrapper
- Decision: SonarCloud configured for Swift project; test code excluded from duplication check; Quality Gate badge added to README; replaced earlier standalone workflow with integrated approach
- Consequences: quality gate blocks merges when issues exceed threshold; duplication detection focused on production code only

- [ ] **Step 5: Research and write ADR-O05 (CodeQL)**

Write to `ClearanceKit/ADRs/operations/ADR-O05-codeql-swift-analysis.md`. Key points:
- Context: security vulnerability scanning for Swift source code
- Options: (1) no CodeQL, (2) automatic build mode, (3) manual build mode, (4) buildless extraction
- Decision: CodeQL with buildless extraction (`build-mode: none`) on macos-26 runner with Xcode 26; actions pinned by SHA; top-level least-privilege permissions declared; switched from manual to buildless after build-mode issues
- Consequences: CodeQL runs on every push; Swift buildless mode trades some analysis depth for reliability; pinned by SHA alongside other actions

- [ ] **Step 6: Research and write ADR-O06 (Dependabot)**

Write to `ClearanceKit/ADRs/operations/ADR-O06-dependabot-supply-chain.md`. Key points:
- Context: GitHub Actions SHA pins and pip packages go stale; manual updates miss security patches
- Options: (1) manual updates, (2) Renovate, (3) Dependabot
- Decision: Dependabot configured for `github-actions` and `pip` ecosystems; auto-merges Dependabot PRs for minor/patch updates after tests pass
- Consequences: SHA pins kept current automatically; pip dependencies (used in release scripts) patched promptly; Copilot auto-merge workflow handles routine updates

- [ ] **Step 7: Research and write ADR-O07 (OpenSSF Scorecard)**

Write to `ClearanceKit/ADRs/operations/ADR-O07-openssf-scorecard.md`. Key points:
- Context: supply chain security posture needs objective measurement and public visibility
- Options: (1) no scorecard, (2) manual assessment only, (3) automated OpenSSF Scorecard workflow
- Decision: OpenSSF Scorecard workflow runs weekly; badge added to README; manual assessment documented in `OPENSSF_SCORECARD_ASSESSMENT.md`; CII Best Practices assessment also completed
- Consequences: public scorecard score; automated checks for branch protection, pinned deps, vulnerability reporting, signed releases; some checks marked N/A (packaging via GitHub releases, not registries)

- [ ] **Step 8: Research and write ADR-O08 (Prerelease versioning)**

Write to `ClearanceKit/ADRs/operations/ADR-O08-prerelease-versioning.md`. Key points:
- Context: every commit to main needs a testable build; users need to distinguish stable from prerelease
- Options: (1) only stable releases, (2) nightly builds with date suffix, (3) prerelease tags based on last stable version
- Decision: prerelease workflow on every main push; version format `<next-minor>-beta-<sha8>`; based on last stable tag (not last prerelease); `-beta-` tags explicitly filtered out when computing next increment
- Consequences: stable releases use clean semver tags; users can install prereleases from GitHub Releases; `gh release create` used (not softprops action) for atomic release + asset upload

- [ ] **Step 9: Research and write ADR-O09 (Zero third-party dependencies)**

Write to `ClearanceKit/ADRs/operations/ADR-O09-zero-third-party-deps.md`. Key points:
- Context: third-party Swift dependencies add supply chain risk, update overhead, and potential licence conflicts for a security-focused tool
- Options: (1) use SwiftPM packages freely, (2) vet and allow selected packages, (3) zero third-party dependencies policy
- Decision: no third-party Swift packages; all functionality implemented using Apple frameworks (EndpointSecurity, Security, AppKit, SwiftUI, SQLite3) and Swift stdlib; highlighted as a feature in README
- Consequences: no SwiftPM dependency graph; no supply chain attack surface from package registries; all capabilities must be implemented or sourced from Apple frameworks; documented explicitly in README and GitHub Pages site

---

## Task 6: Architecture Overview, Components, and Glossary

**Run in parallel with Tasks 2, 3, 4, 5.**

Write the top-level documentation: architecture overview, one note per major component, and a glossary.

**Files to write:**
- `ClearanceKit/Architecture Overview.md`
- `ClearanceKit/Components/opfilter.md`
- `ClearanceKit/Components/clearancekit-gui.md`
- `ClearanceKit/Components/xpc-layer.md`
- `ClearanceKit/Components/policy-engine.md`
- `ClearanceKit/Components/process-tree.md`
- `ClearanceKit/Glossary.md`

**Research commands:**
```bash
cat /Users/craigjbass/Projects/clearancekit/CLAUDE.md
cat /Users/craigjbass/Projects/clearancekit/README.md
ls /Users/craigjbass/Projects/clearancekit/opfilter/
ls /Users/craigjbass/Projects/clearancekit/Shared/
ls /Users/craigjbass/Projects/clearancekit/clearancekit/
ls /Users/craigjbass/Projects/clearancekit/opfilter/Filter/
ls /Users/craigjbass/Projects/clearancekit/opfilter/XPC/
ls /Users/craigjbass/Projects/clearancekit/opfilter/Policy/
ls /Users/craigjbass/Projects/clearancekit/opfilter/Database/
ls /Users/craigjbass/Projects/clearancekit/opfilter/EndpointSecurity/
```

- [ ] **Step 1: Read source material**

Run all research commands above. Read CLAUDE.md in full. Read README.md introduction and architecture section.

- [ ] **Step 2: Write Architecture Overview**

Use `mcp__obsidian-mcp-tools__create_vault_file` with path `ClearanceKit/Architecture Overview.md`. Content must include:

```markdown
# ClearanceKit Architecture Overview

ClearanceKit is a macOS File Access Authorization (FAA) tool that intercepts file system events via the Endpoint Security framework and enforces policy rules based on process code signing identity.

## Process Topology

Two processes collaborate:

- **clearancekit** (GUI app) — SwiftUI menu bar app. Manages rules via Touch ID-gated XPC calls. Displays events and metrics. No direct ES or file system access.
- **opfilter** (System Extension) — Privileged process holding the ES client. Evaluates all policy. Stores the SQLite database. Communicates with the GUI via NSXPCConnection.

## Hexagonal Architecture

Three layers, strictly separated:

| Layer | Location | Rule |
|-------|----------|------|
| Domain | `Shared/` | Pure Swift — no I/O, no OS frameworks |
| Ports | Protocol files near consumers | Swift protocols only |
| Adapters | `opfilter/` subdirs, `clearancekit/` | Own all OS imports |

## Event Pipeline (opfilter)

1. ES kernel delivers AUTH_OPEN (and other file events) to `ESInboundAdapter`
2. Stage 1 (ES callback thread): global allowlist check → cache lookup → policy evaluation
3. ES respond call (allow/deny + cache flag)
4. Stage 2 (postRespondQueue): audit log → XPC broadcast to GUI

## Policy Evaluation Order

1. Global allowlist (bypass all rules)
2. ES response cache (skip re-evaluation for repeated accesses)
3. Managed (MDM) rules
4. User rules
5. Baseline (built-in Apple process allowances)

## Security Layers

- EC-P256 signed SQLite database (tamper detection)
- Touch ID gate on all policy mutations
- XPC audit token validation (prevent PID spoofing)
- opfilter FAA self-protection rule
- ESTamperResistanceAdapter (block SIGSTOP/SIGKILL)
- SLSA L3 provenance on all releases
- Zero third-party Swift dependencies

## ADR Index

See `ADRs/` for decisions organised by domain:
- [[ADRs/architecture/ADR-A01-hexagonal-architecture|Architecture ADRs]]
- [[ADRs/security/ADR-S01-ec-p256-policy-signing|Security ADRs]]
- [[ADRs/features/ADR-F01-process-ancestry-tracking|Feature ADRs]]
- [[ADRs/operations/ADR-O01-github-actions-release|Operations ADRs]]
```

- [ ] **Step 3: Write opfilter component note**

Path: `ClearanceKit/Components/opfilter.md`. Include: role (System Extension holding ES client), subdirectory structure (`EndpointSecurity/`, `XPC/`, `Database/`, `Policy/`, `Filter/`), key files (`main.swift`, `FilterInteractor`, `ESInboundAdapter`, `ESJailAdapter`, `XPCServer`), responsibilities, what it does NOT do (no SwiftUI, no user interaction).

- [ ] **Step 4: Write clearancekit-gui component note**

Path: `ClearanceKit/Components/clearancekit-gui.md`. Include: role (SwiftUI menu bar app), tab structure (Setup, Policy, Events, Processes, App Protections, Metrics), XPC client for all opfilter communication, Touch ID gate on mutations, preset management, export wizards (Santa, mobileconfig).

- [ ] **Step 5: Write xpc-layer component note**

Path: `ClearanceKit/Components/xpc-layer.md`. Include: `XPCProtocol.swift` in `Shared/` (compiled into both binaries), `XPCServer` (opfilter side), `XPCClient` (GUI side), `ConnectionValidator` (audit token verification), `EventBroadcaster` (push deny events to GUI), `ProcessEnumerator` (enumerate running processes for GUI), key protocol methods (updatePolicy, getEvents, getProcesses, toggleJail).

- [ ] **Step 6: Write policy-engine component note**

Path: `ClearanceKit/Components/policy-engine.md`. Include: `FAAPolicy.swift` (pure domain — evaluation logic), `FAARule` (rule struct with UUID, path, ProcessSignature, enforceOnWriteOnly), `GlobalAllowlist.swift`, `PolicyRepository` (loads rules from SQLite, merges tiers), `PolicySigner` (EC-P256 sign/verify), three-tier evaluation (managed → user → baseline), wildcard path matching, specificity-based rule ordering.

- [ ] **Step 7: Write process-tree component note**

Path: `ClearanceKit/Components/process-tree.md`. Include: `ProcessTree.swift` in `Shared/` (O(1) ancestor lookup), `ProcessIdentity` (pid + pidVersion audit token — prevents PID reuse), FORK/EXEC/EXIT event tracking, initial sweep using `TASK_AUDIT_TOKEN`, lazy ancestry lookup via closure injection, `ProcessTreeProtocol` for testability.

- [ ] **Step 8: Write Glossary**

Path: `ClearanceKit/Glossary.md`. Must include definitions for:

| Term | Definition |
|------|-----------|
| FAA | File Access Authorization — macOS Endpoint Security mechanism for intercepting and allowing/denying file operations |
| ES | Endpoint Security — Apple kernel framework for system security monitoring and enforcement |
| AUTH event | Endpoint Security event requiring a synchronous allow/deny response before the deadline |
| NOTIFY event | Endpoint Security event delivered post-facto for logging/monitoring; no response required |
| opfilter | The ClearanceKit System Extension process that holds the ES client and enforces policy |
| clearancekit | The ClearanceKit GUI app (menu bar) that allows users to manage policy rules |
| XPC | Cross-Process Communication — macOS IPC mechanism used between clearancekit and opfilter |
| audit token | Kernel-provided unforgeable process identity token; safer than PID for authentication |
| ProcessSignature | Pair of (teamID, signingID) used to identify a code-signed process in policy rules |
| FAARule | A policy rule specifying which ProcessSignature can access which path pattern |
| AppPreset | A named bundle of FAARule entries for a specific macOS application |
| Global allowlist | A list of ProcessSignature entries that bypass all FAA policy evaluation |
| Managed policy tier | Rules deployed via MDM (macOS preference key); sit between baseline and user rules |
| Baseline | Built-in Apple system process allowances that cannot be removed by users |
| Policy signing | EC-P256 ECDSA signature over the serialised policy database to detect tampering |
| SLSA L3 | Supply-chain Levels for Software Artifacts Level 3 — provenance attestation for release builds |
| Sigstore | A transparency log and signing framework for verifying software build provenance |
| OpenSSF Scorecard | Open Source Security Foundation automated supply chain security scoring tool |
| Jail | ClearanceKit feature that confines a process to an explicit set of allowed path patterns |
| AccessKind | Enum (read/write) derived from ES open flags; used for write-only rule evaluation |
| Preset drift | Condition where an installed preset's rule set differs from the current built-in version |
| pidVersion | Kernel-assigned version counter per PID, reset on reuse; part of ProcessIdentity |
| TLA+ | Temporal Logic of Actions — formal specification language used to model ES deadline pipeline |
| Santa | Google's macOS binary allowlisting tool; ClearanceKit can export policy in Santa format |
| mobileconfig | Apple MDM configuration profile format; ClearanceKit can export rules as mobileconfig |

---

## Self-Review Checklist

After all tasks complete, verify:
- [ ] All 8 architecture ADRs created at correct paths
- [ ] All 6 security ADRs created at correct paths
- [ ] All 10 feature ADRs created at correct paths
- [ ] All 9 operations ADRs created at correct paths
- [ ] Architecture Overview, 5 Component notes, and Glossary created
- [ ] Every ADR uses the correct frontmatter (id, domain, date, status)
- [ ] No ADR file has placeholder text (TBD, TODO, etc.)
- [ ] Glossary covers all terms used in ADRs
