# XPC Metrics Stream — Opt-In Subscription Design

**Status:** Draft
**Date:** 2026-04-25
**Tracking issue:** #144 — *Only stream necessary events over XPC*

## Context

In v5.0.8 the `folderOpened` allow-event broadcast was made opt-in: GUI clients call `beginAllowEventStream` only while the events screen is visible, and opfilter delivers allow events only to subscribed clients. Deny events still go to all clients, and rule/state/jail/MCP/bundle-updater pushes still fire on connect or change. That work substantially reduced background XPC traffic.

One unconditional source of background traffic remains: `metricsUpdated(_:)`. Opfilter samples the pipeline metrics every 1s on `metricsQueue`, encodes a `PipelineMetricsSnapshot`, and pushes it to *every* connected GUI client regardless of whether any client is rendering the metrics chart. After resume from sleep this is observable as a CPU/battery cost — the GUI receives, decodes, and stores snapshots into `metricsHistory` for a chart that may not be on screen.

This design eliminates that traffic when no client is consuming it, by making the metrics stream subscription-driven in the same shape as the allow-event stream.

## Goals

- Stop the 1Hz `metricsUpdated` push when no client is subscribed.
- Stop the opfilter-side 1Hz sampling timer entirely when no client is subscribed.
- Auto-resume the metrics stream on reconnect when `MetricsView` is the active screen, mirroring v5.0.8's allow-stream resume.
- Cut the post-sleep CPU spike attributable to backed-up `metricsUpdated` calls.

## Non-goals

- Deny event broadcast remains always-on (low rate, kept for parity with current behaviour).
- Allow event stream is unchanged from v5.0.8.
- Backfill or connect-time state pushes (`requestResync`, `userRulesUpdated`, `managedRulesUpdated`, etc.) are unchanged.
- No coalescing, batching, or rate-limiting of folder events.
- No generic stream registry abstraction.

## Approach

Introduce a dedicated `MetricsBroadcaster` in `opfilter/XPC/`, alongside `EventBroadcaster`. It owns:

- the set of GUI clients currently subscribed to the metrics stream,
- the registry of all currently-connected GUI clients (for fan-out),
- a `MetricsTimerControlling` collaborator (protocol seam) that it starts on the `0 → 1` subscriber transition and stops on the `1 → 0` transition.

A new `DispatchSourceMetricsTimer` adapter wraps the existing `DispatchSource.makeTimerSource(...)` from `main.swift`. Its event handler samples `pipeline.metrics()` and `jailInteractor.jailMetrics()` and calls `XPCServer.pushMetrics(...)`, which routes to `MetricsBroadcaster.broadcast(...)`. When no subscribers exist, the timer is suspended — no sampling, no encoding, no push.

The GUI side adds `beginMetricsEventStream()` / `endMetricsEventStream()` on `XPCClient`, called from `MetricsView.onAppear` / `.onDisappear`. A `shouldResumeMetricsStream: @Sendable () -> Bool` closure seam mirrors `shouldResumeAllowEventStream` so the app layer can re-subscribe on reconnect when the metrics screen is still active, without coupling `XPCClient` to a SwiftUI-layer type excluded from the test target.

### Architectural choice

Approach **B** from brainstorming — a dedicated broadcaster — was chosen over:

- **A: extend `EventBroadcaster`** — accumulates concerns (folder events, tamper events, allow-stream subs, metrics subs, timer control) in one type. Rejected: violates SRP per CLAUDE.md.
- **C: generic `StreamRegistry<StreamID>`** — speculative generalisation for one extra stream. Rejected: YAGNI.

The codebase organises `opfilter/XPC/` as one role per file (`EventBroadcaster`, `ConnectionValidator`, `ProcessEnumerator`, `XPCServer`). A `MetricsBroadcaster` matches that pattern.

## Architecture

### New types

**`opfilter/XPC/MetricsTimerControlling.swift`**

```swift
protocol MetricsTimerControlling: AnyObject, Sendable {
    func start()
    func stop()
}
```

Idempotent: double `start()` is a no-op while running; double `stop()` is a no-op while stopped.

**`opfilter/XPC/MetricsBroadcaster.swift`**

State (held under `OSAllocatedUnfairLock<State>`):

- `guiClients: [ObjectIdentifier: NSXPCConnection]` — connections to fan out to.
- `metricsStreamClients: Set<ObjectIdentifier>` — connections currently subscribed.

Public surface:

- `addClient(_:)` / `removeClient(_:)` — connection lifecycle, mirrored by `XPCServer` invalidation handler. `removeClient` also drops any subscription and triggers stop on `1 → 0`.
- `beginStream(for:) -> Bool` — adds to `metricsStreamClients`; on `0 → 1` transition, calls `timerController.start()` outside the lock.
- `endStream(for:) -> Bool` — removes from `metricsStreamClients`; on `1 → 0` transition, calls `timerController.stop()` outside the lock.
- `broadcast(_ snapshot: PipelineMetricsSnapshot)` — fan out `metricsUpdated(_:)` to all `guiClients`. Early-return when subscriber set is empty (defence-in-depth).

Concurrency:

- Locking pattern matches `EventBroadcaster`: capture state transitions and connection lists under the lock, perform proxy calls and timer-controller calls outside the lock to avoid re-entrancy.

**`opfilter/XPC/DispatchSourceMetricsTimer.swift`**

Wraps `DispatchSource.makeTimerSource(queue: metricsQueue)` scheduled at 1s repeating. Holds an `isRunning` flag for idempotency. Handler is injected at construction:

```swift
init(queue: DispatchQueue, sample: @escaping @Sendable () -> Void)
```

Created in `main.swift`; the `sample` closure captures `pipeline`, `jailInteractor`, and `server` and performs the existing snapshot build + `server.pushMetrics(...)` call.

### Modified types

**`Shared/XPCProtocol.swift`** — add to `ServiceProtocol`:

```swift
func beginMetricsEventStream(withReply reply: @escaping (Bool) -> Void)
func endMetricsEventStream(withReply reply: @escaping (Bool) -> Void)
```

**`opfilter/XPC/XPCServer.swift`**

- Hold both `eventBroadcaster: EventBroadcaster` and `metricsBroadcaster: MetricsBroadcaster`.
- Connection accept handler calls `metricsBroadcaster.addClient(connection)` in addition to the existing `eventBroadcaster.addClient(connection)`.
- Connection invalidation handler calls both `removeClient` paths.
- Implement `beginMetricsEventStream` / `endMetricsEventStream` by delegating to `metricsBroadcaster.beginStream(for:)` / `endStream(for:)`.
- `pushMetrics(_:jail:timestamp:)` continues to build the `PipelineMetricsSnapshot`, then calls `metricsBroadcaster.broadcast(snapshot)` instead of `eventBroadcaster.broadcastToAllClients { $0.metricsUpdated(snapshot) }`.
- Register `PipelineMetricsSnapshot.self` as an allowed class on the new selectors so secure decoding succeeds across the new XPC entrypoints.

**`opfilter/main.swift`**

- Construct `DispatchSourceMetricsTimer(queue: metricsQueue) { ... existing snapshot/log/push ... }` and inject into `MetricsBroadcaster`.
- Do **not** call `metricsTimer.resume()` unconditionally. The broadcaster starts the timer on first subscribe.
- Keep the `metricsLogger.info("...")` call inside the sample closure. When the timer is paused, the os_log line pauses with it — acceptable consequence of the design.

**`clearancekit/App/XPCClient.swift`**

- Add `func beginMetricsEventStream()` / `func endMetricsEventStream()`, mirroring the allow-stream methods.
- Add `var shouldResumeMetricsStream: @Sendable () -> Bool = { false }` closure seam.
- On reconnect (post-`requestResync`), if `shouldResumeMetricsStream()` returns true, call `beginMetricsEventStream()` automatically.
- Maintain a small reference count internally so duplicate `beginMetricsEventStream` calls from the SwiftUI layer don't desync server-side state.

**`clearancekit/App/clearancekitApp.swift`**

- Inject `XPCClient.shared.shouldResumeMetricsStream = { NavigationState.shared.isMetricsScreenActive }` at app start.

**`clearancekit/App/NavigationState.swift`**

- Add `@Published var isMetricsScreenActive: Bool = false`.

**`clearancekit/Monitor/Metrics/MetricsView.swift`**

- `.onAppear`: `NavigationState.shared.isMetricsScreenActive = true; XPCClient.shared.beginMetricsEventStream()`.
- `.onDisappear`: `XPCClient.shared.endMetricsEventStream(); NavigationState.shared.isMetricsScreenActive = false`.
- Empty `metricsHistory` is acceptable when first opened — chart already handles `metricsHistory.count < 2` with a "collecting…" placeholder.

## Data flow

### Subscribe (GUI → opfilter)

1. `MetricsView.onAppear` sets `NavigationState.shared.isMetricsScreenActive = true` and calls `XPCClient.beginMetricsEventStream()`.
2. `XPCClient` invokes `ServiceProtocol.beginMetricsEventStream(withReply:)` over XPC.
3. `XPCServer.beginMetricsEventStream` delegates to `metricsBroadcaster.beginStream(for: connection)`.
4. `MetricsBroadcaster.beginStream`:
   - Under lock: insert `ObjectIdentifier(connection)` into the subscriber set; capture `wasEmpty` flag.
   - Outside lock: if `wasEmpty`, call `timerController.start()`.
   - Reply `true`.

### Unsubscribe

1. `MetricsView.onDisappear` calls `XPCClient.endMetricsEventStream()`; `isMetricsScreenActive` flips to false.
2. `XPCServer.endMetricsEventStream` delegates to `metricsBroadcaster.endStream(for: connection)`.
3. `MetricsBroadcaster.endStream`:
   - Under lock: remove identifier; capture `becameEmpty` flag.
   - Outside lock: if `becameEmpty`, call `timerController.stop()`.
   - Reply `true`.

### Sample → broadcast (timer running)

1. `DispatchSourceMetricsTimer` fires every 1s on `metricsQueue`.
2. Handler builds the `PipelineMetricsSnapshot` and calls `xpcServer.pushMetrics(...)`.
3. `XPCServer.pushMetrics` → `metricsBroadcaster.broadcast(snapshot)`.
4. `MetricsBroadcaster.broadcast`:
   - Under lock: if subscriber set is empty, return; otherwise snapshot the `guiClients.values` list.
   - Outside lock: for each connection, `(remoteObjectProxy as? ClientProtocol)?.metricsUpdated(snapshot)`.

### Disconnect

1. `XPCServer` invalidation handler invokes both `eventBroadcaster.removeClient(connection)` and `metricsBroadcaster.removeClient(connection)`.
2. `MetricsBroadcaster.removeClient`:
   - Under lock: drop from `guiClients`; drop from `metricsStreamClients`; capture `becameEmpty` flag if subscriber set just emptied.
   - Outside lock: if `becameEmpty`, call `timerController.stop()`.

### Reconnect resume

1. `XPCClient` re-establishes the connection and completes `requestResync`.
2. `XPCClient` calls `shouldResumeMetricsStream()`. If `true`, it issues `beginMetricsEventStream` again on the new connection — same path as initial subscribe.

## Error handling and edge cases

- **Idempotent timer:** `start()` while running is a no-op; `stop()` while stopped is a no-op. Prevents desync on rapid subscribe/unsubscribe.
- **Broadcast races a concurrent stop:** `MetricsBroadcaster.broadcast` early-returns when the subscriber set is empty, even though the timer should already be stopped — defence-in-depth.
- **XPC fire-and-forget:** `metricsUpdated(_:)` is a one-way callback. Connection failures are surfaced via `NSXPCConnection.invalidationHandler`, which routes through `removeClient`. No additional handling in `MetricsBroadcaster`.
- **Subscribe during teardown:** if a `beginMetricsEventStream` call lands while the connection is invalidating, the reply may never reach the GUI, but server-side state converges correctly when invalidation runs `removeClient`.
- **Reply contract:** both `beginMetricsEventStream` and `endMetricsEventStream` reply `true` on success; `endMetricsEventStream` is idempotent (unsubscribing a non-subscriber is fine).
- **GUI duplicate subscribe calls:** `XPCClient` keeps a small internal reference count so duplicate `beginMetricsEventStream` invocations don't desync the server. Server-side `beginStream` is idempotent for the same connection regardless.

## Testing

Unit-tested at `MetricsBroadcaster` level using a `FakeMetricsTimer: MetricsTimerControlling` that records `start()` / `stop()` invocations.

Suite: `@Suite("MetricsBroadcaster")` in `Tests/MetricsBroadcasterTests.swift`.

| Test | Behaviour pinned |
|---|---|
| `firstSubscriberStartsTimer` | empty → `beginStream` → `fakeTimer.startCount == 1`, `stopCount == 0`. |
| `secondSubscriberDoesNotRestartTimer` | two `beginStream` calls on different connections → `startCount == 1`. |
| `lastUnsubscribeStopsTimer` | two subs, two unsubs → `stopCount == 1` after the second unsub only. |
| `removeClientUnsubscribesAndStopsTimer` | one sub, then `removeClient` → `stopCount == 1`. |
| `removeClientForNonSubscriberLeavesTimerRunning` | one sub on conn A; `removeClient(B)` → no stop. |
| `broadcastWithNoSubscribersDoesNotCallProxy` | `broadcast(...)` with empty subscriber set → no fake-proxy invocation. |
| `broadcastFanOutToAllRegisteredClients` | two clients added, ≥1 subscribed → both proxies receive `metricsUpdated`. |
| `idempotentEndStream` | double `endStream` on the same connection → `stopCount == 1`, no crash. |

`NSXPCConnection` cannot be unit-tested directly. Tests use a `FakeMetricsClient` seam — a value-type wrapper exposing connection identity and a closure-based proxy — so the broadcaster can be exercised without real XPC connections. This mirrors how `EventBroadcaster` allow-stream tests are structured.

Out of scope for unit tests:

- `DispatchSourceMetricsTimer` adapter (pure infrastructure glue, integration-tested only).
- `XPCServer` wiring (adapter; trust the protocol seam).
- GUI `XPCClient.shouldResumeMetricsStream` reconnect resume — a single smoke test mirroring the existing allow-stream resume test (if one exists in the test target) is sufficient.

Verification command: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS'`. All new and existing tests must pass before the change is merged.

## Files touched

**New**

- `opfilter/XPC/MetricsBroadcaster.swift`
- `opfilter/XPC/MetricsTimerControlling.swift`
- `opfilter/XPC/DispatchSourceMetricsTimer.swift`
- `Tests/MetricsBroadcasterTests.swift`

**Modified**

- `Shared/XPCProtocol.swift`
- `opfilter/XPC/XPCServer.swift`
- `opfilter/main.swift`
- `clearancekit/App/XPCClient.swift`
- `clearancekit/App/clearancekitApp.swift`
- `clearancekit/App/NavigationState.swift`
- `clearancekit/Monitor/Metrics/MetricsView.swift`

**Untouched**

- `opfilter/XPC/EventBroadcaster.swift`
- All v5.0.8 allow-event stream code.
- All connect-time state-push paths.
