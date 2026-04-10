# Write-only enforcement for FAA rules

Tracking issue: craigjbass/clearancekit#130

## Goal

Add a per-rule `EnforceOnWriteOnly` flag (boolean) so a rule can be configured
to fire only on write operations. Read-only opens fall through to the next
rule (or default-allow). This unlocks "tamper-protection" use cases —
protecting config files like `/etc/pam.d`, `/etc/ssh`, audio plugin bundles,
the contents of `*.app` bundles — where any process should be able to read the
file but only specific processes should be able to modify it.

## What counts as a write

The classification has to be made once at the Endpoint Security boundary,
where we have access to `fflag` for AUTH_OPEN and the operation type for
everything else. The domain layer should never need to know about `fcntl.h`
constants.

| ES event              | Classification | How                                          |
|-----------------------|----------------|----------------------------------------------|
| AUTH_OPEN             | depends        | `fflag & (FWRITE \| O_APPEND \| O_TRUNC) != 0` |
| AUTH_READDIR          | read           | always                                       |
| AUTH_RENAME           | write          | always                                       |
| AUTH_UNLINK           | write          | always                                       |
| AUTH_LINK             | write          | always                                       |
| AUTH_CREATE           | write          | always                                       |
| AUTH_TRUNCATE         | write          | always                                       |
| AUTH_COPYFILE         | write          | always (destination side is a write)         |
| AUTH_EXCHANGEDATA     | write          | always                                       |
| AUTH_CLONE            | write          | always                                       |

`fflag` is already accessed in `ESInboundAdapter.swift:68` and
`ESJailAdapter.swift:197` so the field is reachable; we just need to read it
when constructing the `FileAuthEvent` for AUTH_OPEN.

The constants `FWRITE`, `O_APPEND`, `O_TRUNC` are POSIX and reachable via
`import Foundation`.

## Architecture

Domain stays free of OS imports. The boundary adapter classifies access mode
once and threads a Swift enum through the rest of the pipeline.

```swift
// Shared/AccessKind.swift  (new)
public enum AccessKind: Sendable {
    case read
    case write
}
```

### FileAuthEvent
Add `accessKind: AccessKind` (set in `ESInboundAdapter.fileAuthEvent`).

### FAARule
Add `enforceOnWriteOnly: Bool` (default `false`). When `true`, the rule only
fires for events with `accessKind == .write`. Read events skip the rule and
the iterator moves to the next one.

### checkFAAPolicy
Threads `accessKind` through. The signature gains a new parameter; the
"first matching rule wins" loop now also skips a rule when its
`enforceOnWriteOnly` is `true` and the access is a read.

```swift
for rule in rules {
    guard pathIsProtected(path, by: rule.protectedPathPrefix) else { continue }
    if rule.enforceOnWriteOnly && accessKind == .read { continue }
    // …existing identity / signature checks…
}
```

`PolicyDecision` gains nothing — a "read of a write-only rule" simply falls
through to `.noRuleApplies` and is recorded as default-allow in the audit log,
which is the right semantics: we never observed it, we never blocked it, no
rule applied.

### Cache safety
ES auth-result caching is keyed on (process, vnode). If we cache an *allow*
for a read, a subsequent write from the same process for the same vnode would
hit the cache and bypass the rule. **Anywhere we hit a write-only rule we
must respond with `cache=false`**, regardless of decision. Today the slow
path already uses `cache=false`; the hot path uses `cache=true` for
`.noRuleApplies` and `.globallyAllowed`. We need a new branch: if any
matching rule has `enforceOnWriteOnly`, the cache flag flips to `false` even
when the decision is "no rule applied".

This is the only sharp edge in the design. Without it the feature is silently
broken — a process that opens a file once for read will be permitted to open
it for write later from the cache.

## Persistence

### JSON (PolicyExportDocument)
`FAARule.Codable` already uses `try?` for optional fields, so adding
`enforceOnWriteOnly` as an optional decode with a `false` default is
back-compatible. Old exports load cleanly; new exports include the field.

Bump `schemaVersion` from 1 → 2 anyway, so we have a marker if we ever need
to detect downgrade.

### MDM / mobileconfig
`ManagedPolicyParser.parseManagedPolicyRule` adds:

```swift
enforceOnWriteOnly: dict["EnforceOnWriteOnly"] as? Bool ?? false
```

`ClearanceKitMobileconfigExporter.faaRuleDict` emits `EnforceOnWriteOnly: true`
when the field is set, and omits it when `false` to keep emitted plists tidy.

The sample `scripts/clearancekit-managed-policy.mobileconfig` and the README
schema table both gain a row for `EnforceOnWriteOnly`.

### Santa export interop
`SantaMobileconfigExporter` already emits an `AllowReadAccess` key in every
watch item (currently hardcoded to `false`). The mapping for the new feature
is direct: `enforceOnWriteOnly == true` → `AllowReadAccess: true` in the
exported watch item. Tests in `Tests/SantaMobileconfigExporterTests.swift`
gain coverage for both polarities of the field.

## GUI

`RuleEditView` gains a `Toggle("Only enforce on writes")` above the Allowed
Process Paths section, with a footer explaining: "When enabled, this rule
only blocks operations that modify files. Any process may read the protected
files."

`DraftRule` and `toRule` gain the new field.

The `PresetsView` rendering of preset rules should show a small "writes only"
badge next to rules with `enforceOnWriteOnly == true` so the operator can
tell at a glance.

## MCP

`add_rule` and `update_rule` gain an `enforce_on_write_only` boolean
parameter:

```swift
toolDef(name: "add_rule", description: "...",
    params: [
        "protected_path_prefix": ...,
        "allowed_signatures": ...,
        "enforce_on_write_only": (type: "boolean",
            description: "When true, the rule only enforces on writes. Reads from any process pass through.",
            required: false),
        "id": ...
    ])
```

`list_rules` and `list_presets` print `[writes only]` next to rules where the
flag is set. `formatRule` is the single place to add this.

## Built-in helpers

The issue lists several use-cases that become viable once this lands. They
are out of scope for this PR but worth noting as follow-ups for a separate
"system tamper protection" preset family, alongside the App Protections
presets:

- `/etc/pam.d/` — PAM stack tamper protection
- `/etc/ssh/` — SSH config tamper protection
- `/Library/Audio/Plug-Ins/` — audio plugin tamper protection
- `/Users/*/Library/Group Containers/group.com.docker/` — docker daemon settings
- `/Applications/*.app/Contents/` — app bundle tamper protection (the
  stretch goal — needs careful exclusion of update mechanisms)

Build presets in a follow-up issue. Don't bundle them here.

## Tests

TDD throughout. New test suites / test cases:

1. **`AccessKindClassifierTests`** (new)
   - Each non-OPEN ES operation classifies correctly (rename → write,
     readdir → read, etc.)
   - AUTH_OPEN with `FREAD` only → read
   - AUTH_OPEN with `FWRITE` → write
   - AUTH_OPEN with `O_APPEND` → write
   - AUTH_OPEN with `O_TRUNC` → write
   - AUTH_OPEN with `FREAD | FWRITE` → write

2. **`PolicyDecisionTests` extensions**
   - Write-only rule allows a read with `.noRuleApplies`
   - Write-only rule denies a write from a non-allowed process
   - Write-only rule plus a downstream all-access rule on the same path:
     reads still default-allow because the write-only rule was the first
     match. (This is a real ordering hazard worth pinning.)
   - Write-only rule with `secondaryPath` set: secondary path is a write
     side, so the write rule still fires. Verify we don't bypass on the
     primary path being a read.

3. **`FileAuthPipelineTests` extensions**
   - When a write-only rule matches, the responder is invoked with
     `cache=false` even for `.noRuleApplies` reads (regression guard
     for the cache-poisoning issue).

4. **`ManagedPolicyParser` tests**
   - `EnforceOnWriteOnly: true` → field is `true` on parsed rule
   - Missing key → field defaults to `false`
   - Invalid type (string instead of bool) → field defaults to `false`,
     no crash

5. **`PolicyExportDocumentTests`**
   - Round-trip a rule with `enforceOnWriteOnly: true`
   - Decode an old document (schema v1) — field defaults to `false`

6. **Mobileconfig exporter tests**
   - `enforceOnWriteOnly: true` produces `EnforceOnWriteOnly` key in dict
   - Default `false` does NOT emit the key (keeps emitted plists tidy)

## Documentation

- `README.md` schema table — add `EnforceOnWriteOnly` row
- `scripts/clearancekit-managed-policy.mobileconfig` — add a commented example
- `docs/documentation.html` — corresponding update

## Work order

Each step is an independent commit:

1. Add `AccessKind` enum in `Shared/`. No callers yet.
2. Add `accessKind` to `FileAuthEvent`; populate it in
   `ESInboundAdapter.fileAuthEvent`. Threads the data through but no rule
   uses it yet.
3. Add `enforceOnWriteOnly` to `FAARule` (default `false`). Codable
   round-trips.
4. Extend `checkFAAPolicy` to accept `accessKind` and skip write-only rules
   on reads. All existing call sites pass `.write` (current behavior is
   preserved because `enforceOnWriteOnly` defaults to `false`).
5. Update `FileAuthPipeline` callers to pass `event.accessKind` and to flip
   the cache flag to `false` when any matching rule has `enforceOnWriteOnly`.
6. Update `checkFAAPolicy` test suite (PolicyDecisionTests extensions).
7. Update `ManagedPolicyParser` for `EnforceOnWriteOnly`. Tests.
8. Update `ClearanceKitMobileconfigExporter`. Tests.
9. Update `SantaMobileconfigExporter` to emit `AllowReadAccess: true` when
   `enforceOnWriteOnly` is set. Tests.
10. Update `RuleEditView` toggle.
11. Update `MCPTools` add_rule / update_rule / list_rules / list_presets.
12. README + sample mobileconfig + docs.

Steps 1–5 are the load-bearing core. Steps 7–11 are surface area.

## Open questions

- **Audit volume**: with `EnforceOnWriteOnly`, we'll see *no* audit log
  entries for reads of the protected path (because they fall to
  `.noRuleApplies` and the audit logger only records covered paths). Is
  that the right call, or should there be a `.allowedAsReadOnly` decision
  so the audit log still shows the activity? Operators might want
  visibility into "who's reading /etc/ssh".
