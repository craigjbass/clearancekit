---
id: ADR-S04
domain: security
date: 2026-03-13
status: Accepted
---
# ADR-S04: Policy Database ACL

## Context

The SQLite database containing policy rules is stored on disk at a path reachable by any process running as the logged-in user or as root. Modifying the database directly — without going through opfilter's XPC interface — would bypass both the Touch ID gate (ADR-S02) and the XPC validation (ADR-S03). Even with EC-P256 signing (ADR-S01) catching the tamper after the fact, a defence-in-depth approach is preferred.

## Options

1. **Filesystem permissions and EC-P256 signature check only** — relies on two controls but provides no pre-write prevention.
2. **FAA self-protection rule only** — opfilter blocks writes to its own database via the ES framework; no filesystem-level enforcement.
3. **Layered defence: filesystem permissions + FAA self-protection rule + signing key ACL** — three independent controls that must all be bypassed for a successful tamper.

## Decision

Three-layer defence applied in `e71379d`:

**(a) Filesystem permissions.** The policy directory is created with permissions `0o700` and owned by root, so non-root processes cannot read or write the database file. The file itself is created with `0o600`.

**(b) FAA self-protection rule for the database path.** opfilter adds a policy rule protecting its own database path at startup. Any process other than opfilter that attempts a write to this path is denied by the ES framework before the write reaches the filesystem. This provides kernel-enforced pre-write prevention even for root processes that would otherwise override filesystem permissions. Note: this rule specifically covers the database path. Protection of opfilter's binary path is a separate rule covered in ADR-S06.

**(c) EC-P256 signing key ACL pinned to opfilter's code signing identity** (see ADR-S01). Even if layers (a) and (b) are bypassed, any tampered content will fail signature verification when opfilter next loads the database.

Key ACL migration from the old permissive format is applied on first daemon startup (`4b89e18`).

## Consequences

- The GUI cannot directly write to the policy database; all mutations must go through the XPC interface, which enforces Touch ID and audit token validation.
- The FAA self-protection rule creates a self-referential enforcement loop: opfilter enforces rules that protect itself. This is resolved by the database being read-only during the ES client startup phase — opfilter loads existing rules before the ES client is active, then the FAA rule takes effect once enforcement begins.
- All three layers must be bypassed for a successful silent tamper. A partial bypass (e.g. filesystem permissions overridden by root) is still caught by the FAA rule or, failing that, by the signature check on next load.
- The FAA self-protection rule is keyed to opfilter's exact signing ID (tightened from team-ID-only to exact signing ID in `8386ae0`), preventing other processes signed by the same team from bypassing the rule.
- Binary-path protection (preventing replacement of the opfilter executable itself) is a separate FAA rule described in ADR-S06.
