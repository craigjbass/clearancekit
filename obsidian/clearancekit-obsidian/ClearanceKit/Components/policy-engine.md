# Policy Engine

The policy engine is the decision-making core of ClearanceKit. It lives entirely in `Shared/FAAPolicy.swift` and `Shared/GlobalAllowlist.swift` as pure Swift — no imports of `EndpointSecurity`, `Foundation` file I/O, or any other adapter framework. Every file-access decision opfilter emits is the return value of a single function: `evaluateAccess`.

## `Shared/FAAPolicy.swift` — domain types

### `ProcessSignature`

```swift
public struct ProcessSignature: Codable, Equatable, Hashable {
    public let teamID: String
    public let signingID: String
}
```

Serialised as the single string `"teamID:signingID"`. Wildcards `*` match any team or any signing ID; `"apple"` is the sentinel team ID for Apple platform binaries (which carry an empty team ID in their ES audit token). See [[ADRs/architecture/ADR-A05-process-signature-identity]].

### `FAARule`

```swift
public struct FAARule: Identifiable, Codable, Equatable {
    public let id: UUID
    public let protectedPathPrefix: String
    public let source: RuleSource                // .builtin | .mdm | .user
    public let allowedProcessPaths: [String]
    public var allowedSignatures: [ProcessSignature]
    public let allowedAncestorProcessPaths: [String]
    public var allowedAncestorSignatures: [ProcessSignature]
    public let enforceOnWriteOnly: Bool
}
```

- `id` is stable across releases — the policy-signing system uses it as a key. Always generated with `uuidgen`.
- `protectedPathPrefix` supports the wildcards documented in [[ADRs/features/ADR-F07-wildcard-matching]]: `*` within a component, `**` across components, `?` for a single character.
- `enforceOnWriteOnly` narrows the rule to write operations (rename, unlink, link, create, truncate, copyfile, exchangedata, clone, and opens with `FWRITE`/`O_APPEND`/`O_TRUNC`). Reads fall through. Rationale in [[ADRs/features/ADR-F05-write-only-rules]].
- `requiresAncestry` is `true` iff either `allowedAncestorProcessPaths` or `allowedAncestorSignatures` is non-empty. The filter uses this to decide whether a hot-path decision is possible.
- `encode(to:)` deliberately omits `enforceOnWriteOnly` when `false`, so the canonical JSON of a default rule remains byte-identical to the original v1 shape. This is what lets existing signatures continue to verify after the field was added.

### `PolicyDecision`

An enum of outcomes:

- `.globallyAllowed`
- `.noRuleApplies` — default allow
- `.allowed(ruleID, ruleName, ruleSource, matchedCriterion)`
- `.denied(ruleID, ruleName, ruleSource, allowedCriteria)`
- `.jailAllowed(ruleID, ruleName, matchedPrefix)`
- `.jailDenied(ruleID, ruleName, allowedPrefixes)`

Each case carries the data needed to log the decision without any further lookup. `PolicyDecision.isAllowed` drives the `es_respond_*` call; `.reason`, `.policyName`, `.policySource`, `.matchedRuleID`, and `.jailedRuleID` feed the `FolderOpenEvent` pushed to the GUI.

## `Shared/GlobalAllowlist.swift` — bypass tier

```swift
public struct AllowlistEntry: Identifiable, Codable {
    public let id: UUID
    public var signingID: String       // "" = path-based entry (any signing ID); "*" = wildcard for any signing ID
    public var processPath: String
    public var platformBinary: Bool    // true → teamID must be "apple"
    public var teamID: String          // additional team constraint
}
```

`AllowlistEntry.matches(processPath:signingID:teamID:)` is the only matching function. An empty `signingID` means the entry is path-based — it matches any signing ID for the given `processPath`. A `signingID` of `"*"` is an explicit wildcard that matches any signing ID regardless of path. `AncestorAllowlistEntry` has the same shape and matching semantics but walks the full ancestor chain in `isGloballyAllowedByAncestry` via `matchesAncestor(path:signingID:teamID:)`. The matcher explicitly supports `signingID == "*"` so MDM operators can bless every binary from a team without enumerating bundle IDs.

Four tiers, first-match-wins, merged in `PolicyRepository.mergedAllowlist()`:

1. `baselineAllowlist` — compiled-in Apple system processes required for macOS to boot and function.
2. XProtect remediator entries — dynamically enumerated from `/Library/Apple/System/Library/CoreServices/XProtect.app` and refreshed whenever the kernel signals a change to that directory.
3. Managed entries from `/Library/Managed Preferences/uk.craigbass.clearancekit.plist`.
4. User entries from the signed SQLite database.

See [[ADRs/features/ADR-F02-global-allowlist]].

## `PolicyRepository` — merging and persistence

`opfilter/Policy/PolicyRepository.swift` is the adapter that turns the tiers into the merged views the filter consumes:

- `mergedRules()` — returns `faaPolicy + managedRules + userRules`. The baseline (`faaPolicy` in `Shared/FAAPolicy.swift`) comes first so its tamper-protection rules (for `/Library/Application Support/clearancekit` and `/etc/pam.d`) cannot be shadowed by later entries.
- `mergedAllowlist()` — returns `baselineAllowlist + xprotectEntries + managedAllowlist + userAllowlist`.
- `mergedAncestorAllowlist()` — same merge, for ancestor entries.
- `mergedJailRules()` — merge of managed and user jail rules.

It conforms to the `PolicyDatabaseProtocol` seam declared in the same file and loads each tier via `DatabaseLoadResult<T>`:

- `.ok(entries)` — signature verified, entries installed.
- `.suspect(entries)` — signature failed. Suspect rules and allowlist entries are held in `pendingSuspect*` state and surfaced to the GUI as a `SignatureIssueNotification`. The GUI prompts the user with Touch ID to approve (re-sign) or reject (discard) the suspect data. Ancestor-allowlist suspects and jail-rule suspects are discarded immediately rather than surfaced, because their blast radius is higher than the cost of re-adding them.

## `PolicySigner` — EC-P256 signing

`opfilter/Policy/PolicySigner.swift` signs the canonical JSON of each tier with an EC-P256 key:

- The key lives in the System Keychain with a `SecAccess` ACL that restricts usage to the opfilter binary. Another process running as root cannot use the key unless it also presents the right code-signing identity.
- The Secure Enclave is intentionally not used. The SE is reached via the `com.apple.ctkd.token-client` per-user LaunchAgent, which is not accessible from system-extension context.
- The signing algorithm is `ecdsaSignatureMessageX962SHA256`.
- `Database.canonicalRulesJSON` must produce byte-identical output across builds for the same rule set. That is why `FAARule.encode(to:)` omits `enforceOnWriteOnly` when it is `false`.

Rationale in [[ADRs/security/ADR-S01-ec-p256-policy-signing]].

## `evaluateAccess` — evaluation steps

```swift
public func evaluateAccess(
    rules: [FAARule],
    allowlist: [AllowlistEntry],
    ancestorAllowlist: [AncestorAllowlistEntry] = [],
    path: String,
    secondaryPath: String? = nil,
    processPath: String,
    teamID: String,
    signingID: String,
    accessKind: AccessKind,
    ancestors: [AncestorInfo]
) -> PolicyDecision
```

The three steps inside `evaluateAccess`:

1. `isGloballyAllowed(allowlist:, processPath:, signingID:, teamID:)` — if the immediate process matches any allowlist tier, return `.globallyAllowed`.
2. `isGloballyAllowedByAncestry(ancestorAllowlist:, ancestors:)` — if any ancestor matches, return `.globallyAllowed`.
3. `checkFAAPolicy(...)` — walk the merged rule set (baseline first, then managed, then user).

### Rule selection inside `checkFAAPolicy`

- Filter to rules whose `protectedPathPrefix` matches the request path via `pathIsProtected`.
- Sort by **path specificity** (number of path components, descending), then by **`enforceOnWriteOnly` first** (so tamper-protection rules take precedence over open carve-outs for the same path), then by original order.
- Walk the sorted list; for each rule:
  - Skip it if `enforceOnWriteOnly` and `accessKind == .read`.
  - Try `allowedProcessPaths`.
  - Try `allowedSignatures` via `ProcessSignature.matches(resolvedTeamID:signingID:)`.
  - Try `allowedAncestorProcessPaths` against the ancestor list.
  - Try `allowedAncestorSignatures`.
  - If none match, return `.denied` with a human-readable description of what *would* have matched.
- If no rule covers the path at all, return `.noRuleApplies`.

For rename/link/copyfile/exchangedata/clone events the adapter also passes a `secondaryPath`; `evaluateAccess` evaluates both and returns the more restrictive result via `moreRestrictiveDecision`.

## Lazy ancestry

The async variant of `evaluateAccess` takes an `@Sendable () async -> [AncestorInfo]` closure rather than concrete ancestor data. It calls the closure only if the allowlist requires ancestry or if a matching rule's `requiresAncestry` is true. This is what allows the two-stage pipeline to short-circuit on the hot path and defer process-tree waits to the slow path. See [[ADRs/features/ADR-F01-process-ancestry-tracking]] and [[ADRs/architecture/ADR-A07-two-stage-file-auth-pipeline]].
