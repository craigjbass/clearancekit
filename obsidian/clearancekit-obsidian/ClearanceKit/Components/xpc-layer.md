# XPC Layer

The XPC layer is the only path between the GUI and opfilter. It is the product's trust boundary: both sides run under different code-signing identities, and every message across the wire is framed, authenticated, and secure-coded.

## `Shared/XPCProtocol.swift`

Lives in `Shared/` because it is the one file that has to be compiled into both binaries — it defines the wire types and both halves of the protocol. Putting it in `Shared/` is the one carve-out in the hexagonal rule: a port can live there only when both the opfilter and clearancekit targets need to link it. See [[ADRs/architecture/ADR-A08-protocol-placement]].

### Constants

```swift
public enum XPCConstants {
    public static let serviceName = "uk.craigbass.clearancekit.opfilter"
    public static let protocolVersion = "2.0"
    public static let teamID = "37KMK6XFTT"
    public static let bundleIDPrefix = "uk.craigbass.clearancekit"
}
```

### Wire types (all `NSSecureCoding`)

- `AncestorInfo` — parent-chain node (path, teamID, signingID, uid, gid).
- `FolderOpenEvent` — a single allow/deny decision: operation, path, secondary path for rename/link, timestamp, PID, process identity, accessAllowed flag, decision reason string, ancestors, matched rule ID, jail rule ID.
- `RunningProcessInfo` — snapshot row (pid, pidVersion, parentPID, parentPIDVersion, path, teamID, signingID, uid, gid).
- `SignatureIssueNotification` — carries suspect user-rules and user-allowlist blobs for Touch-ID-gated resolution.
- `PipelineMetricsSnapshot` — once-per-second cumulative counters (defined in `Shared/PipelineMetricsSnapshot.swift`).
- `TamperAttemptEvent` — a denied signal or suspend/resume attempt against opfilter.

### `@objc ServiceProtocol` (opfilter exports, GUI calls)

- Registration: `registerClient`, `unregisterClient`, `requestResync`, `fetchVersionInfo`.
- Event queries: `fetchRecentEvents`, `fetchRecentTamperEvents`.
- Rule mutations: `addRule`, `updateRule`, `removeRule` (each takes JSON-encoded `NSData` for forward compatibility).
- Allowlist mutations: `addAllowlistEntry`, `removeAllowlistEntry`, `addAncestorAllowlistEntry`, `removeAncestorAllowlistEntry`.
- Jail mutations: `addJailRule`, `updateJailRule`, `removeJailRule`.
- Process queries: `fetchProcessList`, `fetchActiveJailedProcesses`, `fetchProcessTree`.
- Modes and toggles: `beginDiscovery`, `endDiscovery`, `setJailEnabled`, `setMCPEnabled`.
- Signature-issue resolution: `resolveSignatureIssue(approved:)`.

### `@objc ClientProtocol` (GUI exports, opfilter calls)

- Event pushes: `folderOpened(_:)`, `tamperAttemptDenied(_:)`, `metricsUpdated(_:)`.
- Authoritative snapshots: `managedRulesUpdated`, `userRulesUpdated`, `managedAllowlistUpdated`, `userAllowlistUpdated`, `managedAncestorAllowlistUpdated`, `userAncestorAllowlistUpdated`, `managedJailRulesUpdated`, `userJailRulesUpdated`.
- State: `jailEnabledUpdated`, `mcpEnabledUpdated`, `serviceReady(_:)`, `signatureIssueDetected(_:)`.

See [[ADRs/architecture/ADR-A03-xpc-ipc-boundary]] for the decision record.

## `XPCServer` (opfilter side)

Declared in `opfilter/XPC/XPCServer.swift` as the `NSXPCListener` delegate for the Mach service `uk.craigbass.clearancekit.opfilter`.

Lifecycle:

1. `XPCServer.start()` creates the listener and resumes it before any heavy startup work. This lets the GUI connect during opfilter boot and show a loading state. Early clients get `serviceReady(false)`.
2. Once `main.swift` has built the process tree, loaded policy, and constructed every adapter, it calls `XPCServer.configure(_:)` with the `ServerContext` struct holding the `ProcessTreeProtocol`, `PolicyRepository`, `FAAFilterInteractor`, `JailFilterInteractor`, `ESInboundAdapter`, and `ESJailAdapter`.
3. `configure(_:)` pushes a full policy snapshot to every already-connected client.

`XPCServer` owns all reaction logic for GUI calls: rule mutations forward to `PolicyRepository`, apply to the live ES adapters, and re-broadcast the encoded user state to every client via `EventBroadcaster`.

The listener's `shouldAcceptNewConnection` sets up `exportedInterface` and `remoteObjectInterface` with strict `NSSecureCoding` class whitelists for every event and snapshot type, then defers the accept/reject decision to `ConnectionValidator.validate`.

## `ConnectionValidator` (opfilter side)

`opfilter/XPC/ConnectionValidator.swift` enforces three checks on every incoming connection:

1. **Signature.** The audit token is resolved to a `SecCode` via `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit, ...)`. The code is then validated against the requirement `anchor apple generic and certificate leaf[subject.OU] = "37KMK6XFTT"`. Using the audit token rather than the PID is load-bearing: it defeats PID-reuse attacks where an attacker races to replace the connecting process between connection open and validation.
2. **Bundle ID prefix.** `kSecCodeInfoIdentifier` must start with `uk.craigbass.clearancekit`.
3. **Forbidden entitlements.** The client must not carry `com.apple.security.cs.allow-dyld-environment-variables`, `com.apple.security.cs.disable-library-validation`, or `com.apple.security.get-task-allow` — any of these would let an attacker load foreign code into a signed binary. This check is skipped in `DEBUG` builds so Xcode debugging works.

A connection that fails any check is rejected before `resume()` is called, so the remote side never gets proxy objects. See [[ADRs/security/ADR-S03-xpc-audit-token-validation]].

## `EventBroadcaster` (opfilter side)

`opfilter/XPC/EventBroadcaster.swift` maintains the set of registered `NSXPCConnection` clients, keeps a bounded ring of recent events (served back via `fetchRecentEvents` / `fetchRecentTamperEvents`), and fans every new `FolderOpenEvent`, `TamperAttemptEvent`, and metrics snapshot out to each live client's remote proxy. Proxies that fail are removed.

## `ProcessEnumerator` (opfilter side)

`opfilter/XPC/ProcessEnumerator.swift` is the bridge between the live process tree and the GUI's Processes and Process Tree views. `enumerateAll()` scans every running PID, resolves audit tokens, and returns `[RunningProcessInfo]`. `enumerate(pids:)` is the targeted variant used by `fetchActiveJailedProcesses`.

## `NSXPCConnection+AuditToken.swift`

Exposes the private `auditToken` property on `NSXPCConnection` — the kernel-filled token that `ConnectionValidator` consumes. The standard public API exposes only the PID; the private field is the only way to get an unforgeable identity.

## `XPCClient` (GUI side)

`clearancekit/App/XPCClient.swift` is the counterpart. It is an `@MainActor` singleton that:

- Opens `NSXPCConnection(machServiceName:)` with the same `NSSecureCoding` whitelist as the server.
- Calls `registerClient`, then subscribes to every pushed update.
- Publishes combined state via Combine `@Published` properties that every SwiftUI store observes.
- Handles connection interruption: reconnects on a five-second timer and calls `requestResync` to repopulate local caches.
- Batches inbound events on a background flush every three seconds to cap SwiftUI repaint overhead.

The client exposes a thin Swift-native API (`addRule(_:)`, `resolveSignatureIssue(approved:)`, etc.) that stores call after Touch ID succeeds. Stores never touch `NSXPCConnection` themselves.
