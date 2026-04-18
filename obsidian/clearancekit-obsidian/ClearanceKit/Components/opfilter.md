# opfilter

The system extension (`uk.craigbass.clearancekit.opfilter`) that holds the Endpoint Security client and enforces policy. It is the only binary in ClearanceKit with ES and SQLite access; every policy decision the product makes is made here.

## Role

- Receives every file-system AUTH and NOTIFY event the kernel delivers to its ES clients.
- Evaluates `evaluateAccess` from `Shared/FAAPolicy.swift` against merged rules (baseline + MDM + user) plus the global allowlist.
- Responds to the kernel before the deadline via `es_respond_auth_result` / `es_respond_flags_result`.
- Persists user rules, allowlist, jail rules, and feature flags to SQLite at `/Library/Application Support/clearancekit` with EC-P256 signatures.
- Serves the GUI over XPC at the Mach service name `uk.craigbass.clearancekit.opfilter`.

## Subdirectory layout

Each subdirectory of `opfilter/` is an adapter role in the hexagonal architecture.

### `EndpointSecurity/`

Translates Endpoint Security C events into domain types and sends responses back.

- `ESInboundAdapter` — the primary ES client. Subscribes to `AUTH_OPEN`, `AUTH_RENAME`, `AUTH_UNLINK`, `AUTH_LINK`, `AUTH_CREATE`, `AUTH_TRUNCATE`, `AUTH_COPYFILE`, `AUTH_READDIR`, `AUTH_EXCHANGEDATA`, `AUTH_CLONE`, `NOTIFY_WRITE`, plus the `NOTIFY_FORK/EXEC/EXIT` lifecycle events. Routes AUTH events into `FileAuthPipeline`, `NOTIFY_WRITE` events to detect XProtect bundle changes, and lifecycle events into the process tree.
- `ESJailAdapter` — the second ES client dedicated to the jail feature. Tracks jailed processes by audit token, evaluates path access against allowed prefixes, and denies anything outside. See [[ADRs/architecture/ADR-A06-dual-es-client]].
- `ESTamperResistanceAdapter` — a third narrowly scoped ES client that blocks `AUTH_SIGNAL` and `AUTH_PROC_SUSPEND_RESUME` targeting `opfilter` itself. See [[ADRs/security/ADR-S05-tamper-resistance-adapter]].
- `LiveEndpointSecurityAPI` / `EndpointSecurityAPI` — protocol seam around the raw ES C functions so adapters can be tested in isolation.
- `ESProcessRecord` — translates `es_process_t` into a `ProcessRecord` usable by `ProcessTree`.
- `MutePath` — wraps `es_mute_path` to avoid delivery of events the filter is not interested in.
- `AccessKindClassifier` — derives `AccessKind.read` vs `.write` from open flags and event type.

### `XPC/`

The IPC boundary with the GUI. Covered in detail in [[xpc-layer]].

- `XPCServer` — `NSXPCListener` delegate that accepts connections, wires dependencies, and pushes snapshots.
- `ConnectionValidator` — audit-token-based signing check on every incoming connection.
- `EventBroadcaster` — fan-out of `FolderOpenEvent`, `TamperAttemptEvent`, and metrics to all registered GUI clients.
- `ProcessEnumerator` — produces `[RunningProcessInfo]` snapshots for the GUI's Processes and Process Tree views.
- `NSXPCConnection+AuditToken` — category that exposes the private `auditToken` needed by `ConnectionValidator`.

### `Database/`

SQLite persistence for all mutable state.

- `Database` — opens the SQLite file at `/Library/Application Support/clearancekit`, conforms to `PolicyDatabaseProtocol`, and enforces `canonicalRulesJSON` byte-stability for signature verification across upgrades.
- `DatabaseMigrations` — schema migrations.

Rationale in [[ADRs/architecture/ADR-A04-sqlite-persistence]].

### `Policy/`

Loads, signs, and merges policy from each tier.

- `PolicyRepository` — owns the merged view of rules, allowlists, jail rules, and feature flags. Returns `DatabaseLoadResult.ok` or `.suspect` to surface signature issues to the GUI via `signatureIssueDetected`.
- `PolicySigner` — EC-P256 sign/verify using a software key in the System Keychain with an ACL locked to the opfilter binary. Secure Enclave is not accessible from system-extension context; rationale in the file header and in [[ADRs/security/ADR-S01-ec-p256-policy-signing]].
- `ManagedPolicyLoader`, `ManagedAllowlistLoader`, `ManagedJailRuleLoader` — read `/Library/Managed Preferences/uk.craigbass.clearancekit.plist` via `CFPreferences` and produce typed `[FAARule]`, `[AllowlistEntry]`, `[JailRule]`.
- `ManagedPolicyParser`, `ManagedAllowlistParser`, `ManagedJailRuleParser` — pure functions that turn raw CFPreferences dictionaries into domain types. See [[ADRs/features/ADR-F03-managed-policy-tier]].

### `Filter/`

Filter orchestration, the two-stage pipeline, and audit output.

- `FAAFilterInteractor` — the interactor that owns the current rule set and delegates file-auth events to `FileAuthPipeline`.
- `JailFilterInteractor` — the equivalent for jail-client events.
- `FileAuthPipeline` — the two-stage bounded-queue pipeline (`hotPathQueue`, `slowQueue`, `slowWorkerSemaphore`). See [[ADRs/architecture/ADR-A07-two-stage-file-auth-pipeline]].
- `FileAuthTypes` — `FileAuthEvent` and related types that carry a retained `es_message_t` through the pipeline.
- `BoundedQueue` — the shared bounded queue primitive used by both stages.
- `PostRespondHandler` — enqueues audit logging, TTY notification, and XPC broadcast onto `postRespondQueue` after `es_respond_*` has returned.
- `AuditLogger` — structured denial logs to the unified log (`os.Logger`).
- `TTYNotifier` — writes a denial message to the originating TTY if the process has one.
- `AllowlistState` — thread-safe holder for the merged immediate + ancestor allowlists.
- `PipelineMetrics` — atomic counters for the live throughput graph.
- `ProcessTree+ProcessTreeProtocol` — conformance bridge so the `Shared/` domain type satisfies the filter's `ProcessTreeProtocol` seam. See [[ADRs/architecture/ADR-A08-protocol-placement]].
- `ProcessTreeProtocol` — the protocol the filter requires from its process tree collaborator.

## Key source files

- `main.swift` — wires every dependency, starts the XPC server first so the GUI can connect during startup, then scans the initial process tree and starts ES clients. Full startup sequence in the file.
- `ESInboundAdapter.swift` — the ES callback dispatcher.
- `ESJailAdapter.swift` — jail enforcement.
- `FAAFilterInteractor.swift` — filter orchestration.
- `XPCServer.swift` — XPC lifecycle and client-facing `ServiceProtocol` implementation.

## What opfilter does not do

- No SwiftUI, no AppKit, no user interface of any kind. It cannot present dialogs or notifications.
- No direct interaction with the logged-in user. It runs in the system context and has no access to the per-user Keychain or Secure Enclave.
- No network I/O. ClearanceKit has no phone-home, telemetry, or auto-update path.
- No mutation of managed policy — MDM entries are read-only.
- No policy decisions based on anything other than the `evaluateAccess` contract in `Shared/`. Every decision is traceable to a `FAARule` or `AllowlistEntry` that can be inspected in the GUI.
