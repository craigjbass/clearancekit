# Bundle Protection Ancestry Trust — Design

**Date:** 2026-04-22

## Problem

Some updaters spawn sub-processes (e.g. `rsync`, `installer`, `cp`) to perform the actual file writes. These sub-processes are not codesigned by the app bundle's team ID, so the current `BundleProtectionEvaluator` denies them. The trust signal is present in the process ancestry, not on the direct writer.

## Solution

Extend `BundleProtectionEvaluator` with two new ancestry-based allow cases:

1. **Ancestor is a registered updater** — any ancestor in the process tree matches a `BundleUpdaterSignature` entry (full `teamID + signingID` match, or `teamID`-only if `signingID == "*"`)
2. **Ancestor is the bundle self-signer** — any ancestor's `teamID` matches the target bundle's signing `teamID`

## Wildcard Support in `BundleUpdaterSignature`

`signingID = "*"` means "trust any process signed by this team ID". Wildcards apply consistently to both direct-process matching and ancestry matching — so a wildcard entry trusts the registered process itself and any subprocess it spawns.

## Updated Evaluation Order

```
1. Direct process matches BundleUpdaterSignature        (existing)
2. Ancestor matches BundleUpdaterSignature              (NEW)
3. Direct process is com.apple.DesktopServicesHelper    (existing)
4. Direct process teamID matches bundle signing teamID  (existing)
5. Ancestor teamID matches bundle signing teamID        (NEW)
6. Deny
```

Ancestry checks are placed adjacent to their direct-process counterparts. System helper remains between updater ancestry and self-signer checks — its trust is scoped to Apple-signed platform binaries and is not ancestry-based.

## Matching Rules

**Direct process matching (updated):**
```
signingID == "*"  →  match on teamID only
otherwise         →  match on teamID AND signingID
```

**Ancestry matching:**
```
For BundleUpdaterSignature ancestors:
  signingID == "*"  →  ancestor.teamID == sig.teamID
  otherwise         →  ancestor.teamID == sig.teamID AND ancestor.signingID == sig.signingID

For bundle self-signer ancestors:
  ancestor.teamID == bundleSigningTeamID
```

## Interface Change

`BundleProtectionEvaluator.evaluate()` gains an `ancestors` parameter:

```swift
func evaluate(
    accessPath: String,
    processTeamID: String,
    processSigningID: String,
    processUID: UInt32,
    accessKind: AccessKind,
    ancestors: [AncestorInfo]
) -> PolicyDecision?
```

The slow path in `FileAuthPipeline` already fetches `ancestors` from `ProcessTree` before calling `evaluate()`, so the call site change is minimal.

## Components Affected

| Component | Change |
|-----------|--------|
| `Shared/BundleUpdaterSignature.swift` | Add wildcard matching logic |
| `opfilter/Filter/BundleProtectionEvaluator.swift` | Add `ancestors` parameter; add two new allow cases; apply wildcard to direct match |
| `opfilter/Filter/FileAuthPipeline.swift` | Pass `ancestors` to `evaluate()` |
| Tests | New cases for ancestry allow, ancestry deny, wildcard direct, wildcard ancestry |

## Testing

- Registered updater spawns unsigned subprocess → allowed via ancestor match
- Registered updater with wildcard spawns subprocess → allowed via ancestor teamID match
- Unrelated process spawns subprocess → denied (no trusted ancestor)
- App self-updater spawns `rsync` → allowed via bundle self-signer ancestor
- Ancestry chain has no matching team → denied
- Existing direct-match cases unchanged
- Wildcard `signingID == "*"` on direct process match → allowed
