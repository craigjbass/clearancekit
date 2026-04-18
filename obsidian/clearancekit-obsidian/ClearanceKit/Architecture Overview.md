# Architecture Overview

ClearanceKit is a macOS file-access authorisation tool that places Apple's Endpoint Security framework between every file-system access attempt and the process that triggered it, enforcing policy bound to code-signing identity.

## Process topology

Two code-signed binaries run in separate processes:

- **`opfilter`** — a system extension (bundle ID `uk.craigbass.clearancekit.opfilter`, team ID `37KMK6XFTT`). Holds two Endpoint Security clients, owns the SQLite policy database, and makes allow/deny decisions. No user interface.
- **`clearancekit`** — a SwiftUI menu-bar application (`uk.craigbass.clearancekit`). Connects to `opfilter` over XPC to read events and mutate policy. Has no direct Endpoint Security or SQLite access.

The GUI may crash, restart, or be uninstalled without affecting enforcement: `opfilter` continues to apply policy even with no GUI attached.

## Hexagonal architecture

The codebase is organised so that the domain — the logic that evaluates policy — has no knowledge of Endpoint Security, XPC, SQLite, SwiftUI, or any other infrastructure.

| Layer | Location | Contents |
|-------|----------|----------|
| Domain | `Shared/` | Pure Swift with no I/O or framework dependencies: `FAAPolicy.swift`, `GlobalAllowlist.swift`, `ProcessTree.swift`, `JailRule.swift`, `AccessKind.swift`, `CacheDecisionProcessor.swift`. Compiled into both binaries. |
| Ports | Defined beside their consumers | Protocols the domain and filter layer need from the outside: `ProcessTreeProtocol`, `PolicyDatabaseProtocol`, `ServiceProtocol` / `ClientProtocol` in `XPCProtocol.swift`. |
| Adapters | `opfilter/EndpointSecurity/`, `opfilter/XPC/`, `opfilter/Database/`, `opfilter/Policy/`, `opfilter/Filter/`, and the `clearancekit/` GUI | Translate between external systems (ES, XPC, SQLite, SwiftUI) and domain types. |

Domain code never imports `EndpointSecurity`, `AppKit`, `SwiftUI`, `SQLite`, or `LocalAuthentication`. Rationale in [[ADRs/architecture/ADR-A01-hexagonal-architecture]] and [[ADRs/architecture/ADR-A08-protocol-placement]].

## Event pipeline

The kernel delivers each file-system event to `opfilter` through a two-stage pipeline. Full diagram in the project `README.md`; stages summarised here:

1. **ES callback (kernel context).** `ESInboundAdapter` receives the raw `es_message_t`. Lifecycle events (`NOTIFY_FORK`, `NOTIFY_EXEC`, `NOTIFY_EXIT`) update the `ProcessTree`. AUTH events are retained and handed to the filter pipeline.
2. **Stage 1 — hot path.** `FileAuthPipeline` classifies the event via `classifyPath`. If no rule applies, or the matching rule only needs process-level criteria, the decision is computed inline on `hotPathQueue` and `es_respond_*` is called immediately. The pipeline bounds its input at 1024 events; drops shed load as allow.
3. **ES respond (deadline-bounded).** Every AUTH event must be answered before the kernel deadline or the kernel auto-denies and kills the client.
4. **Stage 2 — slow path.** Events whose matching rule requires ancestry are placed on `slowQueue` (bounded at 256) and processed by up to two concurrent workers gated by `slowWorkerSemaphore`. A worker waits for the process tree to catch up (deadline − 100 ms) and then evaluates with full ancestry.
5. **Post-respond.** After responding, the event moves to `postRespondQueue` for audit logging (`AuditLogger`), TTY denial notification (`TTYNotifier`), and XPC broadcast to GUI clients (`EventBroadcaster`).

Full rationale in [[ADRs/architecture/ADR-A07-two-stage-file-auth-pipeline]] and [[ADRs/features/ADR-F08-es-response-caching]].

## Policy evaluation order

`evaluateAccess` in `Shared/FAAPolicy.swift` resolves each access request through a strict order, first match wins:

1. **Global allowlist** (immediate process). A match against any tier — baseline, managed, or user — returns `.globallyAllowed` without consulting rules. See [[ADRs/features/ADR-F02-global-allowlist]].
2. **Ancestor allowlist.** If any ancestor in the calling chain matches an allowlist entry, the request is globally allowed. Requires ancestry data.
3. **FAA rules.** `checkFAAPolicy` selects matching rules by path pattern, sorts by path specificity (more components wins) and by `enforceOnWriteOnly` (tamper-protection rules before general rules), then walks the first match. Each rule checks allowed process paths, allowed signatures, allowed ancestor paths, and allowed ancestor signatures in that order.
4. **Baseline.** Built-in Apple system process allowances and tamper-protection of `/Library/Application Support/clearancekit` and `/etc/pam.d` sit in `faaPolicy` and are merged into the ruleset at the top of the list.

After `es_respond_*` is called, `CacheDecisionProcessor` controls whether the kernel-level ES cache bit is set on the response — it does not short-circuit in-process evaluation. `FileAccessEventCacheDecisionProcessor.decide(outcome:ancestorEvaluationRequired:)` returns `false` (no cache) for deny outcomes that required ancestry, so the kernel re-evaluates future requests through opfilter rather than serving a stale cached result. See [[ADRs/features/ADR-F08-es-response-caching]].

Rules come from three sources (`RuleSource`): `.builtin`, `.mdm`, and `.user`, corresponding to the baseline, managed, and user tiers. See [[ADRs/features/ADR-F03-managed-policy-tier]].

## Security layers

Defence in depth against on-device attackers that already have user-level code execution:

- **EC-P256 policy signing.** The on-disk SQLite rule set is signed with an ECDSA-P256 key stored in the System Keychain with an ACL restricting use to `opfilter`. Tampered rows fail verification and are quarantined as `DatabaseLoadResult.suspect`. See [[ADRs/security/ADR-S01-ec-p256-policy-signing]].
- **Touch ID on policy mutations.** The GUI gates every policy, allowlist, and jail-rule mutation on `LAContext.deviceOwnerAuthentication`. See [[ADRs/security/ADR-S02-touch-id-policy-mutations]].
- **XPC audit-token validation.** `ConnectionValidator` reads each incoming connection's audit token, resolves it to a `SecCode`, and requires Apple anchor + team ID `37KMK6XFTT` + bundle ID prefix `uk.craigbass.clearancekit` + absence of entitlements that weaken code-signing integrity. See [[ADRs/security/ADR-S03-xpc-audit-token-validation]].
- **FAA self-protection.** The baseline policy protects `/Library/Application Support/clearancekit` so only the opfilter binary signed by the ClearanceKit team can read or write rule storage. See [[ADRs/security/ADR-S04-policy-database-acl]] and [[ADRs/security/ADR-S06-opfilter-self-protection]].
- **`ESTamperResistanceAdapter`.** Subscribes to `AUTH_SIGNAL` and `AUTH_PROC_SUSPEND_RESUME` events targeting the `opfilter` PID and denies them in-kernel. Denied attempts surface to the GUI as `TamperAttemptEvent`. See [[ADRs/security/ADR-S05-tamper-resistance-adapter]].
- **SLSA L3 provenance.** Release builds produce signed Sigstore attestations via GitHub Actions. See [[ADRs/operations/ADR-O02-slsa-l3-provenance]] and [[ADRs/operations/ADR-O01-github-actions-release]].
- **Zero third-party dependencies.** Every capability comes from Apple frameworks; no package manager, no vendored library. See [[ADRs/operations/ADR-O09-zero-third-party-deps]].

## ADR index

### Architecture
- [[ADRs/architecture/ADR-A01-hexagonal-architecture]]
- [[ADRs/architecture/ADR-A02-daemon-gui-separation]]
- [[ADRs/architecture/ADR-A03-xpc-ipc-boundary]]
- [[ADRs/architecture/ADR-A04-sqlite-persistence]]
- [[ADRs/architecture/ADR-A05-process-signature-identity]]
- [[ADRs/architecture/ADR-A06-dual-es-client]]
- [[ADRs/architecture/ADR-A07-two-stage-file-auth-pipeline]]
- [[ADRs/architecture/ADR-A08-protocol-placement]]

### Security
- [[ADRs/security/ADR-S01-ec-p256-policy-signing]]
- [[ADRs/security/ADR-S02-touch-id-policy-mutations]]
- [[ADRs/security/ADR-S03-xpc-audit-token-validation]]
- [[ADRs/security/ADR-S04-policy-database-acl]]
- [[ADRs/security/ADR-S05-tamper-resistance-adapter]]
- [[ADRs/security/ADR-S06-opfilter-self-protection]]

### Features
- [[ADRs/features/ADR-F01-process-ancestry-tracking]]
- [[ADRs/features/ADR-F02-global-allowlist]]
- [[ADRs/features/ADR-F03-managed-policy-tier]]
- [[ADRs/features/ADR-F04-preset-system]]
- [[ADRs/features/ADR-F05-write-only-rules]]
- [[ADRs/features/ADR-F06-app-jail]]
- [[ADRs/features/ADR-F07-wildcard-matching]]
- [[ADRs/features/ADR-F08-es-response-caching]]
- [[ADRs/features/ADR-F09-preset-drift-detection]]
- [[ADRs/features/ADR-F10-mcp-server-research-tool]]

### Operations
- [[ADRs/operations/ADR-O01-github-actions-release]]
- [[ADRs/operations/ADR-O02-slsa-l3-provenance]]
- [[ADRs/operations/ADR-O03-actions-sha-pinning]]
- [[ADRs/operations/ADR-O04-codeql-swift-analysis]]
- [[ADRs/operations/ADR-O05-sonarcloud-analysis]]
- [[ADRs/operations/ADR-O06-dependabot-supply-chain]]
- [[ADRs/operations/ADR-O07-openssf-scorecard]]
- [[ADRs/operations/ADR-O08-prerelease-versioning]]
- [[ADRs/operations/ADR-O09-zero-third-party-deps]]

## Component notes

- [[Components/opfilter]]
- [[Components/clearancekit-gui]]
- [[Components/xpc-layer]]
- [[Components/policy-engine]]
- [[Components/process-tree]]

See also [[Glossary]] for domain terminology.
