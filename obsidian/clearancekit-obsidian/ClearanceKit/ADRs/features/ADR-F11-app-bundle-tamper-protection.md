---
id: ADR-F11
domain: features
date: 2026-04-18
status: Accepted
---
# ADR-F11: App Bundle Tamper Protection

## Context

Malicious or compromised processes can overwrite executables inside installed `.app` bundles — replacing signed binaries with trojaned versions that survive across app relaunches. ClearanceKit's existing FAA policy operates on user-defined rules and does not distinguish between a legitimate app updating itself and an unrelated process injecting code into a foreign bundle. Issue #133.

## Options

1. **Domain-level rule type** — add a new `FAARule` kind that captures "protect this bundle". Requires changes to `FAAPolicy`, encoding, DB schema, GUI rule editor, and canonical JSON signing. High coupling to core domain types.

2. **Adapter-layer pre-evaluation** — intercept bundle writes before `checkFAAPolicy` in `FileAuthPipeline`. Resolve signing identity from disk, compare against the bundle's own code-signing identity, and return a `PolicyDecision` without touching domain types. Isolated: new files in `opfilter/Filter/`, one new table, one XPC message pair.

3. **Static bundle list** — let users add specific bundle paths to a protected list with no automatic signing lookup. Simple, but requires manual maintenance and provides no automatic protection for bundles the user hasn't explicitly registered.

## Decision

**Option 2: adapter-layer pre-evaluation.**

Three new files in `opfilter/Filter/`:

- **`BundlePath`** — pure namespace. `extract(from:)` finds the enclosing `.app` under `/Applications/` or `~/Applications/`. `/System/Applications/` is excluded (SIP covers it).
- **`BundleCodesignCache`** — TTL-based (60 s) cache of bundle signing identities. On miss, enumerates executables in `Contents/MacOS/`, `Contents/XPCServices/*/Contents/MacOS/`, `Contents/Helpers/`, and `Contents/Library/LoginItems/*/Contents/MacOS/`, calling `SecStaticCodeCreateWithPath` + `SecCodeCopySigningInformation` for each. Stores `BundleSignatures { teamID: String, signingIDs: Set<String> }`. Invalidated when a `_CodeSignature` write is observed for the same bundle.
- **`BundleProtectionEvaluator`** — combines cache with a user-managed external-updater list. `isBundleWrite(path:accessKind:)` gates the slow path. `evaluate(...)` returns `PolicyDecision?`: `nil` means fall through to normal policy.

Self-signer check requires **both** team ID match **and** signing ID membership in the bundle's signing ID set. Team ID alone is insufficient — multiple apps from the same developer share a team ID.

Unsigned bundles fall through (no enforcement): requiring all bundles to be signed would block legitimate unsigned tooling.

External updaters (e.g. Sparkle) are user-managed via a `bundle_updater_signatures` SQLite table (migration 008), signed with the same EC-P256 scheme as other tables. Suspect handling applies: on signature failure the list is empty (fail-closed).

Pipeline integration: `FileAuthPipeline.processHotPath` forces any bundle write to the slow path via `isBundleWrite`. `processSlowPath` calls `evaluate` before `checkFAAPolicy`; a non-nil decision short-circuits the rest of the policy evaluation.

## Consequences

- Domain types (`FAARule`, `PolicyDecision`, `checkFAAPolicy`) are unchanged.
- Bundle write classification requires a disk-backed codesign lookup on first access (slow path) and is cached for 60 s thereafter. Negligible impact on the hot path.
- Unsigned bundles receive no protection. This is intentional: failing closed on unsigned software would block legitimate developer workflows.
- Self-updating apps that sign their updater with the same team ID and a signing ID present in the bundle (e.g. the app itself spawning a helper) work without configuration.
- Sparkle and other external updaters must be explicitly added to the `bundle_updater_signatures` allowlist. The GUI exposes a `BundleUpdaterAllowlistView` for this.
- Cache invalidation on `_CodeSignature` writes ensures that legitimate re-signing (e.g. after an update) is reflected within one write cycle, not after a 60 s TTL expiry.
