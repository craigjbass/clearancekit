# App Bundle Tamper Protection — Design Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent malicious processes from writing to `.app` bundle contents by dynamically resolving each bundle's code-signing identity and enforcing that only processes signed within the same bundle (or user-approved external updaters) may write to it.

**Architecture:** Adapter-layer pre-evaluation (`opfilter/Filter/`) runs before normal `checkFAAPolicy`. Domain types (`FAARule`, `PolicyDecision`, `checkFAAPolicy`) are untouched. The pipeline routes bundle writes to the slow path for disk-backed codesign lookup. A user-managed `bundle_updater_signatures` table (signed, same as other tables) stores approved external updaters.

**Tech Stack:** Swift, Security.framework (`SecStaticCodeCreateWithPath`, `SecCodeCopySigningInformation`), SQLite, NSXPCConnection, SwiftUI.

---

## Scope

Protected path prefixes (writes only):
- `/Applications/*.app/**`
- `{NSHomeDirectory()}/Applications/*.app/**`

`/System/Applications/` excluded — SIP protects it.

---

## New Files

| File | Purpose |
|------|---------|
| `opfilter/Filter/BundlePath.swift` | Pure function: extract `.app` bundle path from any sub-path |
| `opfilter/Filter/BundleCodesignCache.swift` | TTL cache of bundle signing IDs; invalidated by `_CodeSignature` writes |
| `opfilter/Filter/BundleProtectionEvaluator.swift` | Combines cache + updater list → `PolicyDecision?` |
| `Tests/BundlePathTests.swift` | Unit tests for path extraction |
| `Tests/BundleCodesignCacheTests.swift` | Cache behaviour tests |
| `Tests/BundleProtectionEvaluatorTests.swift` | Evaluator decision tests |

## Modified Files

| File | Change |
|------|--------|
| `Shared/BundleUpdaterSignature.swift` | New: `BundleUpdaterSignature` domain type |
| `Shared/XPCProtocol.swift` | New XPC messages for bundle updater signatures |
| `opfilter/Database/DatabaseMigrations.swift` | Migration 008: `bundle_updater_signatures` table |
| `opfilter/Database/Database.swift` | Load/save/sign bundle updater signatures |
| `opfilter/Policy/PolicyRepository.swift` | Handle `.suspect` for new table |
| `opfilter/Filter/FAAFilterInteractor.swift` | Wire `BundleProtectionEvaluator` into pipeline |
| `opfilter/Filter/FileAuthPipeline.swift` | Hot path: detect bundle writes → slow path; slow path: evaluator pre-check |
| `opfilter/main.swift` | Construct `BundleProtectionEvaluator`, wire `postRespond` invalidation |
| `clearancekit/App/XPCClient.swift` | Handle `bundleUpdaterSignaturesUpdated`, expose `bundleUpdaterSignatures` |
| `clearancekit/Configure/` | New `BundleUpdaterAllowlistView` |
| `Tests/CanonicalBundleUpdaterEncodingTests.swift` | Pin canonical JSON encoding |

---

## Component Design

### BundlePath

Pure namespace — no state.

```swift
enum BundlePath {
    static let protectedPrefixes: [String] = [
        "/Applications/",
        NSHomeDirectory() + "/Applications/"
    ]

    /// Returns the enclosing .app path, or nil if not under a protected bundle prefix.
    static func extract(from accessPath: String) -> String?
}
```

Algorithm: for each protected prefix, check if `accessPath` has that prefix, then find the first path component ending in `.app` after the prefix, return everything up to and including it.

Edge cases:
- Path IS the bundle root → returns it
- No `.app` component → `nil`
- Nested `.app` (e.g. `/Applications/Foo.app/Contents/PlugIns/Bar.app/`) → returns outer `.app`
- `~` not expanded → won't match (caller uses `NSHomeDirectory`)

### BundleCodesignCache

```swift
struct BundleSignatures {
    let teamID: String
    let signingIDs: Set<String>
    let expiry: Date
}

final class BundleCodesignCache: @unchecked Sendable {
    private let ttl: TimeInterval  // default 60s
    private let storage: OSAllocatedUnfairLock<[String: BundleSignatures]>

    /// Returns nil if bundle is unsigned (empty teamID).
    func signatures(forBundlePath: String) -> BundleSignatures?

    /// Call when a _CodeSignature write is observed for this bundle.
    func invalidate(bundlePath: String)
}
```

On cache miss, enumerate executables in the bundle and collect signing IDs:
- `{bundle}/Contents/MacOS/*`
- `{bundle}/Contents/XPCServices/*/Contents/MacOS/*`
- `{bundle}/Contents/Helpers/*`
- `{bundle}/Contents/Library/LoginItems/*/Contents/MacOS/*`

For each candidate: call `SecStaticCodeCreateWithPath` then `SecCodeCopySigningInformation(kSecCSSigningInformation)`. Extract `kSecCodeInfoIdentifier` (signingID) and `kSecCodeInfoTeamIdentifier` (teamID). Skip files where the call fails (non-Mach-O, ad-hoc signed, etc.).

If no signed executables found → `teamID = ""` → return `nil`.

All signing IDs found must share the same `teamID`; if they don't, use the main executable's teamID and include only signing IDs matching it.

### BundleProtectionEvaluator

```swift
final class BundleProtectionEvaluator: @unchecked Sendable {
    init(
        cache: BundleCodesignCache,
        updaterSignaturesProvider: @escaping @Sendable () -> [BundleUpdaterSignature]
    )

    /// Hot-path gate: should this event be forced to the slow path?
    func isBundleWrite(path: String, accessKind: AccessKind) -> Bool

    /// Slow-path evaluation. Returns nil → not a bundle or bundle unsigned → fall through.
    func evaluate(
        accessPath: String,
        processTeamID: String,
        processSigningID: String,
        accessKind: AccessKind
    ) -> PolicyDecision?
}
```

`isBundleWrite` logic:
```
accessKind == .write && BundlePath.extract(from: path) != nil
```

`evaluate` logic:
1. `BundlePath.extract(from: accessPath)` → `nil` → return `nil`
2. Read-only access → return `nil` (reads unrestricted)
3. `cache.signatures(forBundlePath:)` → `nil` (unsigned) → return `nil`
4. Check external updater: `updaterSignatures.contains { $0.teamID == processTeamID && $0.signingID == processSigningID }` → `.allowed(..., matchedCriterion: "external updater")`
5. Check self-signer: `processTeamID == bundleSignatures.teamID && bundleSignatures.signingIDs.contains(processSigningID)` → `.allowed(..., matchedCriterion: "bundle self-signer")`
6. Otherwise → `.denied(..., allowedCriteria: "bundle signing identity \(bundleSignatures.teamID)")`

`PolicyDecision` fields for bundle decisions: use a stable sentinel UUID (generated once with `uuidgen`, stored as a constant), `ruleName = bundlePath`, `ruleSource = .builtin`.

### Pipeline Integration

**Hot path** (`processHotPath`, before classification switch):
```swift
if bundleProtectionEvaluator.isBundleWrite(path: event.path, accessKind: event.accessKind) {
    enqueueToSlowPath(event, rules: rules, allowlist: allowlist, ancestorAllowlist: ancestorAllowlist)
    return
}
```

**Slow path** (`processSlowPath`, before `evaluateAccess`):
```swift
let ancestors = processTree.ancestors(of: event.processIdentity)
if let decision = bundleProtectionEvaluator.evaluate(
    accessPath: event.path,
    processTeamID: event.teamID,
    processSigningID: event.signingID,
    accessKind: event.accessKind
) {
    event.respond(decision.isAllowed, false)
    postRespondHandler(event, decision, ancestors, dwellNanoseconds)
    return
}
```

**Cache invalidation** (in `postRespond` closure in `main.swift`):
```swift
if event.accessKind == .write, event.path.contains("/_CodeSignature/"),
   let bundlePath = BundlePath.extract(from: event.path) {
    bundleCodesignCache.invalidate(bundlePath: bundlePath)
}
```

`FileAuthPipeline` gains `bundleProtectionEvaluator: BundleProtectionEvaluator?` (optional, default `nil` so existing tests don't need to change).

---

## Persistence — BundleUpdaterSignature

### Domain type (`Shared/BundleUpdaterSignature.swift`, new file)

```swift
@objc(BundleUpdaterSignature)
public class BundleUpdaterSignature: NSObject, NSSecureCoding, Sendable {
    public let id: UUID
    public let teamID: String
    public let signingID: String
}
```

### Migration 008

```sql
CREATE TABLE bundle_updater_signatures (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL,
    signing_id TEXT NOT NULL
)
```

### Database methods

```swift
func loadBundleUpdaterSignaturesResult() -> DatabaseLoadResult<BundleUpdaterSignature>
func saveBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature])
```

Canonical JSON: sorted by `id.uuidString`, `JSONEncoder` with `.sortedKeys`. Stored in `data_signatures` under key `"bundle_updater_signatures"`. `tableHasRows` gains the new case.

### Signing / suspect handling

`PolicyRepository` gains `pendingSuspectBundleUpdaterSignatures` — same pattern as other suspect tables. On suspect: empty list used (fail-closed). GUI signature issue flow covers this table.

### XPC messages

`ClientProtocol`:
```swift
func bundleUpdaterSignaturesUpdated(_ signaturesData: NSData)
```

`ServiceProtocol`:
```swift
func saveBundleUpdaterSignatures(_ signaturesData: NSData)
```

XPC interface registers `BundleUpdaterSignature.self` + `NSArray.self` for the new message.

---

## GUI — BundleUpdaterAllowlistView

New view in `clearancekit/Configure/` (alongside `AllowlistView`). Shows list of `BundleUpdaterSignature` rows: display name (from signingID), teamID. Add button opens process picker (same as existing allowlist). Remove button per row. Changes call `saveBundleUpdaterSignatures`.

Navigation entry added to `ContentView` or settings sidebar.

---

## Testing

### BundlePathTests
- `/Applications/Foo.app/Contents/MacOS/Foo` → `/Applications/Foo.app`
- `~/Applications/Bar.app/Contents/Resources/icon.png` → `{home}/Applications/Bar.app`
- `/usr/bin/git` → `nil`
- Path IS bundle root → returns it
- Nested `.app` → outer `.app`
- No `.app` component → `nil`

### BundleCodesignCacheTests
- Cache miss → reads from fake codesign provider → returns `BundleSignatures`
- Second call within TTL → uses cached value (provider not called again)
- Call after TTL expiry → re-reads
- `invalidate` → next call re-reads
- Unsigned bundle (no signed executables) → returns `nil`

Use a seam: `BundleCodesignCache` accepts a `signatureReader: (String) -> (teamID: String, signingID: String)?` closure injection for testing.

### BundleProtectionEvaluatorTests
- Non-bundle path → `nil`
- Read access to bundle → `nil`
- Unsigned bundle (cache returns nil) → `nil`
- Team ID mismatch → `.denied`
- Team ID match, signing ID not in set → `.denied`
- Team ID match, signing ID in set → `.allowed` ("bundle self-signer")
- External updater exact match → `.allowed` ("external updater")
- External updater team ID match but wrong signing ID → `.denied`

### Pipeline integration
- Bundle write event routes to slow path (not handled on hot path)
- Non-bundle write handled on hot path as normal
- Bundle read NOT routed to slow path by `isBundleWrite`

### CanonicalBundleUpdaterEncodingTests
- Default-field encoding pins byte-level JSON
- Round-trip encode/decode preserves all fields
