---
id: ADR-F12
domain: features
date: 2026-04-19
status: Accepted
supersedes: ADR-F11 (self-signer check; system file helper exception)
---
# ADR-F12: Bundle Protection Trust Model Refinements

## Context

ADR-F11 established app bundle tamper protection. Two aspects of the trust model proved incorrect in practice after observing real deny events:

**Self-signer check too strict.** ADR-F11 required the writing process to match *both* the bundle's team ID *and* have its signing ID present in the set of signing IDs enumerated from `Contents/MacOS/`. In practice, Squirrel-family updaters (e.g. Discord's ShipIt, `teamID: 53Q6R32WPB`) run as a separate binary that is **not** installed inside the app bundle's `Contents/MacOS/`. ShipIt renames the entire bundle root as part of an atomic swap update. It carries the correct team ID but its signing ID is absent from the bundle's enumerated set, so it was incorrectly denied.

**Finder drag operations blocked.** Moving a bundle in `/Applications/` via Finder (e.g. to Trash, or between volumes) is performed by `com.apple.DesktopServicesHelper` running as `root`. This process has no relationship to the bundle being moved, so it can never satisfy the self-signer check. Without an explicit exception it was denied, making it impossible to remove apps through Finder.

## Options — Self-Signer Check

1. **Expand enumeration** — also scan `Contents/Frameworks/`, embedded XPC services, login items, etc. to widen the signing ID set. Incomplete by design: an updater helper distributed separately from the bundle will never appear inside it.

2. **Team ID only** — trust any process whose team ID matches the bundle's team ID. Rationale: team ID is bound to an Apple Developer account and signing certificate. Controlling the team ID means controlling the private key that signed the bundle; a different developer cannot forge this. The self-signer check's purpose is "are you the author of this bundle?" — team ID answers that question without requiring signing ID enumeration.

3. **User-managed self-signer allowlist** — require users to add their own updater binaries to the external-updater table. Correct but imposes manual configuration burden for first-party updater patterns (same developer, different binary).

## Options — System File Helper

1. **No exception** — treat `DesktopServicesHelper` like any other process. Users cannot move bundles via Finder. Not acceptable.

2. **Signing ID only** — allow any process whose signing ID is `com.apple.DesktopServicesHelper`. Spoofable: a third-party binary could be signed with that signing ID string if Apple's reserved namespace were not enforced by the kernel.

3. **Platform binary + signing ID + root UID** — require all three: `is_platform_binary` (enforced by Endpoint Security; the `appleTeamID` sentinel is set by the adapter from `es_process_t.is_platform_binary`), signing ID `com.apple.DesktopServicesHelper`, and `uid == 0`. All three must hold simultaneously. A spoofed signing ID without a valid Apple platform binary certificate fails the platform check. A compromised non-root process fails the UID check.

## Decision

**Self-signer: Option 2 — team ID only.**

The self-signer criterion in `BundleProtectionEvaluator.evaluate` checks `processTeamID == bundleSignatures.teamID`. Signing ID enumeration is removed from `BundleCodesignCache`; `BundleSignatures` now stores only `teamID`.

**System file helper: Option 3 — platform binary + signing ID + root UID.**

```swift
if processTeamID == appleTeamID
    && processSigningID == "com.apple.DesktopServicesHelper"
    && processUID == 0 {
    return .allowed(..., matchedCriterion: "system file helper")
}
```

`processUID` is threaded through `FileAuthPipeline` from `FileAuthEvent.uid` (already present) into `BundleProtectionEvaluator.evaluate`.

**Bundle root protection: always enforced.**

An earlier experimental commit excluded bundle root path itself from protection (allowing any process to rename the entire `.app`). This was reverted: renaming the bundle root is the primary attack vector for bundle-swap attacks (rename legitimate app out, place trojan in its place). Bundle root writes are subject to the full self-signer / external updater / system file helper evaluation.

## Consequences

- Squirrel/ShipIt-family updaters with correct team ID are allowed without user configuration.
- Any process from a different developer team attempting to write into or rename a signed bundle is denied.
- Finder bundle moves (via root `DesktopServicesHelper`) work normally.
- `BundleCodesignCache` is simpler: `signatureReader` returns `String?` (team ID only); no `Set<String>` for signing IDs.
- Team-ID-only trust is weaker than signing-ID-scoped trust within a single developer account. A malicious process signed by the same developer (same team ID) can write to that developer's bundles. This is the accepted trade-off: intra-account trust boundaries are not a goal of this feature. The external-updater allowlist remains available for strict signing-ID-scoped control of third-party updaters.
