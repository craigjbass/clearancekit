# Process Tree

The process tree is the in-memory ancestry map opfilter consults whenever a policy rule or ancestor allowlist requires parent-chain information. It lives in `Shared/ProcessTree.swift` and is the canonical example of the "hexagonal core" in this codebase: a stateful service that never touches Endpoint Security directly — it receives already-translated `ProcessRecord` values from the adapter layer.

## `Shared/ProcessTree.swift`

`ProcessTree` is a thread-safe store keyed by `ProcessIdentity`. All state lives behind an `OSAllocatedUnfairLock` so the filter can read ancestry from multiple pipeline stages concurrently. Its public surface:

```swift
func insert(_ record: ProcessRecord)
func remove(identity: ProcessIdentity)
func contains(identity: ProcessIdentity) -> Bool
func ancestors(of identity: ProcessIdentity) -> [AncestorInfo]
func allRecords() -> [ProcessRecord]
func buildInitialTree()
```

Internally it maintains three dictionaries: a primary `[ProcessIdentity: ProcessRecord]`, a `pidIndex` that maps bare PIDs back to the current identity, and an `ancestorCache` that memoises the resolved parent chain so repeated lookups are O(1).

## `ProcessIdentity`

```swift
struct ProcessIdentity: Hashable {
    let pid: pid_t
    let pidVersion: UInt32
}
```

`pidVersion` is the kernel-assigned counter exposed in `audit_token_t.val[7]`. It increments every time a PID is reused. Keying on `(pid, pidVersion)` rather than `pid` alone is load-bearing: when the kernel recycles a PID between two processes, the old record has the old version and the new record has a fresh one, so a lookup never hits a stale record. See [[ADRs/architecture/ADR-A05-process-signature-identity]] for the identity rationale.

## Event-driven maintenance

`ESInboundAdapter` translates lifecycle events into `ProcessRecord` values and hands them to `FAAFilterInteractor`, which dispatches onto `processTreeQueue` and calls the tree:

- `ES_EVENT_TYPE_NOTIFY_FORK` → `interactor.handleFork(child:)` → `processTree.insert(child)`.
- `ES_EVENT_TYPE_NOTIFY_EXEC` → `interactor.handleExec(newImage:)` → `processTree.insert(newImage)`. Insertion overwrites any existing record for the same `pid` where the old `pidVersion` differs, clearing the previous ancestor-cache entry.
- `ES_EVENT_TYPE_NOTIFY_EXIT` → `interactor.handleExit(identity:)` → `processTree.remove(identity:)`, but **deferred by 60 seconds** via `evictionQueue.asyncAfter`. The retention window gives in-flight file-auth evaluations time to look up ancestors for a process that has already exited.

A process created before opfilter launches has no fork/exec event, so the tree bootstraps itself via `buildInitialTree()` on startup (see below).

## `buildInitialTree()` — the startup scan

On the very first run of opfilter each boot, the ES client has seen no fork or exec events for processes that were already running. `main.swift` calls `processTree.buildInitialTree()` after starting the XPC server but before starting the ES client. The scan:

1. `proc_listallpids` — enumerates every live PID.
2. For each PID, `task_name_for_pid` + `task_info(TASK_AUDIT_TOKEN)` produces the audit token. `val.7` of that token is the `pidVersion`.
3. `proc_pidinfo(PROC_PIDTBSDINFO)` provides `pbi_ppid`, `pbi_uid`, `pbi_gid`.
4. `proc_pidpath` produces the executable path.
5. `secCode(forPID:)` + `codeSigningInfo(for:)` resolve teamID and signingID. `isApplePlatformBinary` uses `SecRequirementCreateWithString("anchor apple", ...)` to map an empty teamID to the sentinel `"apple"`.
6. Records are inserted and the ancestor cache is rebuilt in a single topological pass, sorting by PID so parents precede children.

The XPC server is intentionally started first (see `main.swift`) so the GUI can connect during the scan and show a loading state rather than spinning on an unreachable Mach service.

## Lazy ancestry lookup

The filter never fetches ancestors eagerly. `FileAuthPipeline` classifies every event via `classifyPath` (from `Shared/FAAPolicy.swift`); classification returns one of:

- `.noRuleApplies` — respond immediately, no tree read.
- `.processLevelOnly` — evaluate inline on the hot path, no tree read.
- `.ancestryRequired` — route to the slow path.

Only the slow path ever passes an `@Sendable () async -> [AncestorInfo]` closure to `evaluateAccess`, and the async variant of `checkFAAPolicy` inside it calls the closure only if the allowlist needs ancestry or if a matching rule's `requiresAncestry` is true. A slow-path worker also spins on `processTree.contains` until the identity is present or the kernel deadline is 100 ms away — this closes the race where a just-spawned child triggers an AUTH event before its `NOTIFY_EXEC` has been processed. See [[ADRs/architecture/ADR-A07-two-stage-file-auth-pipeline]] and [[ADRs/features/ADR-F01-process-ancestry-tracking]].

## `ProcessTreeProtocol` — the seam

`opfilter/Filter/ProcessTreeProtocol.swift` declares the subset of `ProcessTree` the filter actually needs:

```swift
protocol ProcessTreeProtocol {
    func insert(_ record: ProcessRecord)
    func remove(identity: ProcessIdentity)
    func contains(identity: ProcessIdentity) -> Bool
    func ancestors(of identity: ProcessIdentity) -> [AncestorInfo]
    func allRecords() -> [ProcessRecord]
}
```

The protocol lives in `opfilter/Filter/` — the consumer of the abstraction, not the implementor, per [[ADRs/architecture/ADR-A08-protocol-placement]]. The conformance `extension ProcessTree: ProcessTreeProtocol` sits in `opfilter/Filter/ProcessTree+ProcessTreeProtocol.swift` rather than in `Shared/`, which keeps the domain type free of the adapter-layer dependency.

The seam is what lets characterisation tests for the pipeline drive ancestry behaviour without standing up a real `ProcessTree`: tests provide a `FakeProcessTree` conforming to the protocol.
