# XPC Metrics Stream Opt-In Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the opfilter→GUI metrics stream subscription-driven so the 1Hz `metricsUpdated` push and the underlying sampling timer halt entirely while no GUI client is rendering the metrics chart.

**Architecture:** Introduce a dedicated `MetricsBroadcaster` in `opfilter/XPC/` alongside the existing `EventBroadcaster`. The broadcaster owns its own GUI client registry and the metrics-stream subscriber set, and drives a `MetricsTimerControlling` collaborator (started on `0→1` subscriber transition, stopped on `1→0`). A `DispatchSourceMetricsTimer` adapter wraps the existing `DispatchSource` timer from `main.swift`. The GUI subscribes from `MetricsView.onAppear` and unsubscribes from `.onDisappear`, with a `shouldResumeMetricsStream` closure seam mirroring v5.0.8's allow-stream resume on reconnect.

**Tech Stack:** Swift, `OSAllocatedUnfairLock`, `NSXPCConnection`, `DispatchSource` timer, Swift Testing (`@Suite`/`@Test`/`#expect`), `xcodebuild`.

**Reference:** spec at `docs/superpowers/specs/2026-04-25-xpc-metrics-stream-opt-in-design.md`. Issue #144.

---

## File structure

| File | Role |
|---|---|
| `opfilter/XPC/MetricsTimerControlling.swift` (new) | Protocol seam for the 1Hz timer; only `start()` and `stop()`. |
| `opfilter/XPC/MetricsBroadcaster.swift` (new) | Tracks subscribed GUI clients, fans out `metricsUpdated`, drives the timer on subscriber transitions. |
| `opfilter/XPC/DispatchSourceMetricsTimer.swift` (new) | Concrete `MetricsTimerControlling` wrapping `DispatchSource.makeTimerSource(...)`. |
| `Tests/MetricsBroadcasterTests.swift` (new) | Swift Testing suite covering subscriber transitions, timer control, idempotency. |
| `Shared/XPCProtocol.swift` (modify) | Add `beginMetricsEventStream` / `endMetricsEventStream` to `ServiceProtocol`. |
| `opfilter/XPC/XPCServer.swift` (modify) | Hold `MetricsBroadcaster`; route `pushMetrics` through it; register/remove clients on it; expose new entrypoints. |
| `opfilter/main.swift` (modify) | Build `DispatchSourceMetricsTimer` + `MetricsBroadcaster`; remove unconditional `metricsTimer.resume()`. |
| `clearancekit/App/XPCClient.swift` (modify) | Add `beginMetricsEventStream` / `endMetricsEventStream`, `shouldResumeMetricsStream` seam, internal subscribe ref-count, reconnect resume. |
| `clearancekit/App/clearancekitApp.swift` (modify) | Inject `shouldResumeMetricsStream = { NavigationState.shared.isMetricsScreenActive }`. |
| `clearancekit/App/NavigationState.swift` (modify) | Add `isMetricsScreenActive` computed property. |
| `clearancekit/Monitor/Metrics/MetricsView.swift` (modify) | Subscribe on appear, unsubscribe on disappear. |

---

## Task 1: `MetricsTimerControlling` protocol

**Files:**
- Create: `opfilter/XPC/MetricsTimerControlling.swift`

- [ ] **Step 1: Create the protocol file**

```swift
//
//  MetricsTimerControlling.swift
//  opfilter
//

import Foundation

/// Drives the 1Hz pipeline-metrics sampling timer. Implementations must be idempotent:
/// `start()` while running is a no-op, `stop()` while stopped is a no-op.
protocol MetricsTimerControlling: AnyObject, Sendable {
    func start()
    func stop()
}
```

- [ ] **Step 2: Build to confirm it compiles**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS'`
Expected: BUILD SUCCEEDED.

- [ ] **Step 3: Commit**

```bash
git add opfilter/XPC/MetricsTimerControlling.swift
git commit -m "feat: add MetricsTimerControlling protocol seam"
```

---

## Task 2: `MetricsBroadcaster` — empty type with init

**Files:**
- Create: `opfilter/XPC/MetricsBroadcaster.swift`

- [ ] **Step 1: Create the type with an empty State and the timer-controller dependency**

```swift
//
//  MetricsBroadcaster.swift
//  opfilter
//
//  Owns the subscription set for the metricsUpdated stream and drives the
//  1Hz sampling timer on subscriber-count transitions. Lives next to
//  EventBroadcaster but keeps metrics concerns isolated so neither type
//  accumulates responsibilities.
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "metrics-broadcaster")

final class MetricsBroadcaster: @unchecked Sendable {
    private struct State {
        var guiClients: [ObjectIdentifier: NSXPCConnection] = [:]
        var streamClients: Set<ObjectIdentifier> = []
        var timerRunning: Bool = false
    }

    private let storage: OSAllocatedUnfairLock<State>
    private let timerController: MetricsTimerControlling

    init(timerController: MetricsTimerControlling) {
        self.storage = OSAllocatedUnfairLock(initialState: State())
        self.timerController = timerController
    }
}
```

- [ ] **Step 2: Build**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS'`
Expected: BUILD SUCCEEDED.

- [ ] **Step 3: Commit**

```bash
git add opfilter/XPC/MetricsBroadcaster.swift
git commit -m "feat: add MetricsBroadcaster scaffold with timer controller"
```

---

## Task 3: Test fixture — fake timer + first subscribe starts timer

**Files:**
- Create: `Tests/MetricsBroadcasterTests.swift`

- [ ] **Step 1: Write the first failing test with a private `FakeMetricsTimer`**

```swift
//
//  MetricsBroadcasterTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("MetricsBroadcaster")
struct MetricsBroadcasterTests {

    private final class FakeMetricsTimer: MetricsTimerControlling, @unchecked Sendable {
        private let lock = OSAllocatedUnfairLock<(starts: Int, stops: Int)>(initialState: (0, 0))
        var startCount: Int { lock.withLock { $0.starts } }
        var stopCount: Int { lock.withLock { $0.stops } }
        func start() { lock.withLock { $0.starts += 1 } }
        func stop()  { lock.withLock { $0.stops += 1 } }
    }

    @Test("first subscriber starts the timer")
    func firstSubscriberStartsTimer() {
        let timer = FakeMetricsTimer()
        let broadcaster = MetricsBroadcaster(timerController: timer)
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)

        broadcaster.beginStream(for: conn)

        #expect(timer.startCount == 1)
        #expect(timer.stopCount == 0)
    }
}
```

- [ ] **Step 2: Run the test and confirm it fails to compile**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/MetricsBroadcaster/firstSubscriberStartsTimer`
Expected: COMPILE FAIL — `addClient` and `beginStream` not defined on `MetricsBroadcaster`.

- [ ] **Step 3: Implement `addClient` + `beginStream` on `MetricsBroadcaster`**

Add these methods to `opfilter/XPC/MetricsBroadcaster.swift`:

```swift
@discardableResult
func addClient(_ connection: NSXPCConnection) -> Int {
    storage.withLock { state in
        state.guiClients[ObjectIdentifier(connection)] = connection
        return state.guiClients.count
    }
}

@discardableResult
func beginStream(for connection: NSXPCConnection) -> Bool {
    let shouldStart = storage.withLock { state -> Bool in
        let id = ObjectIdentifier(connection)
        let wasEmpty = state.streamClients.isEmpty
        state.streamClients.insert(id)
        if wasEmpty && !state.timerRunning {
            state.timerRunning = true
            return true
        }
        return false
    }
    if shouldStart { timerController.start() }
    return true
}
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/MetricsBroadcaster/firstSubscriberStartsTimer`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Tests/MetricsBroadcasterTests.swift opfilter/XPC/MetricsBroadcaster.swift
git commit -m "feat: MetricsBroadcaster.beginStream starts timer on first subscriber"
```

---

## Task 4: Second subscriber does not restart timer

**Files:**
- Modify: `Tests/MetricsBroadcasterTests.swift`

- [ ] **Step 1: Add the failing test**

Append inside the `MetricsBroadcasterTests` suite:

```swift
@Test("second subscriber does not restart the timer")
func secondSubscriberDoesNotRestartTimer() {
    let timer = FakeMetricsTimer()
    let broadcaster = MetricsBroadcaster(timerController: timer)
    let connA = NSXPCConnection()
    let connB = NSXPCConnection()
    broadcaster.addClient(connA)
    broadcaster.addClient(connB)

    broadcaster.beginStream(for: connA)
    broadcaster.beginStream(for: connB)

    #expect(timer.startCount == 1)
}
```

- [ ] **Step 2: Run the test**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/MetricsBroadcaster/secondSubscriberDoesNotRestartTimer`
Expected: PASS (logic from Task 3 already short-circuits on non-empty subscriber set).

- [ ] **Step 3: Commit**

```bash
git add Tests/MetricsBroadcasterTests.swift
git commit -m "test: cover repeat-subscribe leaves metrics timer running once"
```

---

## Task 5: Last unsubscribe stops the timer

**Files:**
- Modify: `Tests/MetricsBroadcasterTests.swift`
- Modify: `opfilter/XPC/MetricsBroadcaster.swift`

- [ ] **Step 1: Add the failing test**

Append inside the suite:

```swift
@Test("last unsubscribe stops the timer")
func lastUnsubscribeStopsTimer() {
    let timer = FakeMetricsTimer()
    let broadcaster = MetricsBroadcaster(timerController: timer)
    let connA = NSXPCConnection()
    let connB = NSXPCConnection()
    broadcaster.addClient(connA)
    broadcaster.addClient(connB)
    broadcaster.beginStream(for: connA)
    broadcaster.beginStream(for: connB)

    broadcaster.endStream(for: connA)
    #expect(timer.stopCount == 0)

    broadcaster.endStream(for: connB)
    #expect(timer.stopCount == 1)
}
```

- [ ] **Step 2: Run and confirm compile failure**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/MetricsBroadcaster/lastUnsubscribeStopsTimer`
Expected: COMPILE FAIL — `endStream` not defined.

- [ ] **Step 3: Add `endStream` to `MetricsBroadcaster`**

Append to `opfilter/XPC/MetricsBroadcaster.swift`:

```swift
@discardableResult
func endStream(for connection: NSXPCConnection) -> Bool {
    let shouldStop = storage.withLock { state -> Bool in
        state.streamClients.remove(ObjectIdentifier(connection))
        if state.streamClients.isEmpty && state.timerRunning {
            state.timerRunning = false
            return true
        }
        return false
    }
    if shouldStop { timerController.stop() }
    return true
}
```

- [ ] **Step 4: Run the test**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/MetricsBroadcaster/lastUnsubscribeStopsTimer`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Tests/MetricsBroadcasterTests.swift opfilter/XPC/MetricsBroadcaster.swift
git commit -m "feat: MetricsBroadcaster.endStream stops timer on final unsubscribe"
```

---

## Task 6: `removeClient` cleans up subscription and stops timer

**Files:**
- Modify: `Tests/MetricsBroadcasterTests.swift`
- Modify: `opfilter/XPC/MetricsBroadcaster.swift`

- [ ] **Step 1: Add two failing tests**

Append inside the suite:

```swift
@Test("removeClient unsubscribes and stops the timer")
func removeClientUnsubscribesAndStopsTimer() {
    let timer = FakeMetricsTimer()
    let broadcaster = MetricsBroadcaster(timerController: timer)
    let conn = NSXPCConnection()
    broadcaster.addClient(conn)
    broadcaster.beginStream(for: conn)

    broadcaster.removeClient(conn)

    #expect(timer.stopCount == 1)
}

@Test("removeClient for a non-subscriber leaves the timer running")
func removeClientForNonSubscriberLeavesTimerRunning() {
    let timer = FakeMetricsTimer()
    let broadcaster = MetricsBroadcaster(timerController: timer)
    let connA = NSXPCConnection()
    let connB = NSXPCConnection()
    broadcaster.addClient(connA)
    broadcaster.addClient(connB)
    broadcaster.beginStream(for: connA)

    broadcaster.removeClient(connB)

    #expect(timer.stopCount == 0)
    #expect(timer.startCount == 1)
}
```

- [ ] **Step 2: Run and confirm compile failure**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/MetricsBroadcaster`
Expected: COMPILE FAIL — `removeClient` not defined.

- [ ] **Step 3: Implement `removeClient`**

Append to `opfilter/XPC/MetricsBroadcaster.swift`:

```swift
@discardableResult
func removeClient(_ connection: NSXPCConnection) -> Int {
    let (clientCount, shouldStop) = storage.withLock { state -> (Int, Bool) in
        let id = ObjectIdentifier(connection)
        state.guiClients.removeValue(forKey: id)
        let didRemoveSubscriber = state.streamClients.remove(id) != nil
        let shouldStop = didRemoveSubscriber
            && state.streamClients.isEmpty
            && state.timerRunning
        if shouldStop { state.timerRunning = false }
        return (state.guiClients.count, shouldStop)
    }
    if shouldStop { timerController.stop() }
    return clientCount
}
```

- [ ] **Step 4: Run the tests**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/MetricsBroadcaster`
Expected: all four MetricsBroadcaster tests PASS.

- [ ] **Step 5: Commit**

```bash
git add Tests/MetricsBroadcasterTests.swift opfilter/XPC/MetricsBroadcaster.swift
git commit -m "feat: MetricsBroadcaster.removeClient drops subscription and stops timer"
```

---

## Task 7: Idempotent `endStream`

**Files:**
- Modify: `Tests/MetricsBroadcasterTests.swift`

- [ ] **Step 1: Add the failing test**

Append:

```swift
@Test("double endStream is idempotent")
func doubleEndStreamIsIdempotent() {
    let timer = FakeMetricsTimer()
    let broadcaster = MetricsBroadcaster(timerController: timer)
    let conn = NSXPCConnection()
    broadcaster.addClient(conn)
    broadcaster.beginStream(for: conn)

    broadcaster.endStream(for: conn)
    broadcaster.endStream(for: conn)

    #expect(timer.stopCount == 1)
}
```

- [ ] **Step 2: Run the test**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/MetricsBroadcaster/doubleEndStreamIsIdempotent`
Expected: PASS (the existing `state.timerRunning` guard makes the second `endStream` a no-op).

- [ ] **Step 3: Commit**

```bash
git add Tests/MetricsBroadcasterTests.swift
git commit -m "test: cover idempotent metrics endStream"
```

---

## Task 8: `broadcast` no-ops when no subscribers

**Files:**
- Modify: `Tests/MetricsBroadcasterTests.swift`
- Modify: `opfilter/XPC/MetricsBroadcaster.swift`

- [ ] **Step 1: Add the failing test**

Append (inside the suite):

```swift
private func makeSnapshot() -> PipelineMetricsSnapshot {
    PipelineMetricsSnapshot(
        eventBufferEnqueueCount: 0,
        eventBufferDropCount: 0,
        hotPathProcessedCount: 0,
        hotPathRespondedCount: 0,
        slowQueueEnqueueCount: 0,
        slowQueueDropCount: 0,
        slowPathProcessedCount: 0,
        jailEvaluatedCount: 0,
        jailDenyCount: 0,
        timestamp: Date()
    )
}

@Test("broadcast with no subscribers does not throw")
func broadcastWithNoSubscribersDoesNotThrow() {
    let timer = FakeMetricsTimer()
    let broadcaster = MetricsBroadcaster(timerController: timer)
    let conn = NSXPCConnection()
    broadcaster.addClient(conn)

    broadcaster.broadcast(makeSnapshot())

    // Subscriber set was empty so no proxy fan-out occurred — broadcast must
    // tolerate that path without crashing or affecting timer state.
    #expect(timer.startCount == 0)
    #expect(timer.stopCount == 0)
}
```

(Move the existing `private final class FakeMetricsTimer` and any other private helpers above any `@Test` functions if file ordering becomes awkward. The compiler is fine with helpers anywhere inside the suite struct.)

- [ ] **Step 2: Run and confirm compile failure**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/MetricsBroadcaster/broadcastWithNoSubscribersDoesNotThrow`
Expected: COMPILE FAIL — `broadcast` not defined.

- [ ] **Step 3: Implement `broadcast`**

Append to `opfilter/XPC/MetricsBroadcaster.swift`:

```swift
/// Fans out the snapshot to every connected GUI client whenever ≥1 client is
/// subscribed. Returns immediately when the subscriber set is empty.
func broadcast(_ snapshot: PipelineMetricsSnapshot) {
    let connections = storage.withLock { state -> [NSXPCConnection] in
        guard !state.streamClients.isEmpty else { return [] }
        return Array(state.guiClients.values)
    }
    for conn in connections {
        (conn.remoteObjectProxy as? ClientProtocol)?.metricsUpdated(snapshot)
    }
}
```

- [ ] **Step 4: Run the test**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/MetricsBroadcaster/broadcastWithNoSubscribersDoesNotThrow`
Expected: PASS.

- [ ] **Step 5: Run the whole suite to confirm no regressions**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/MetricsBroadcaster`
Expected: all six tests PASS.

- [ ] **Step 6: Commit**

```bash
git add Tests/MetricsBroadcasterTests.swift opfilter/XPC/MetricsBroadcaster.swift
git commit -m "feat: MetricsBroadcaster.broadcast no-ops without subscribers"
```

---

## Task 9: `DispatchSourceMetricsTimer` adapter

**Files:**
- Create: `opfilter/XPC/DispatchSourceMetricsTimer.swift`

- [ ] **Step 1: Create the adapter**

```swift
//
//  DispatchSourceMetricsTimer.swift
//  opfilter
//
//  Wraps a DispatchSource timer that fires once per second on the metrics
//  queue. Owns an isRunning flag so start()/stop() are idempotent.
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "metrics-timer")

final class DispatchSourceMetricsTimer: MetricsTimerControlling, @unchecked Sendable {
    private let timer: DispatchSourceTimer
    private let lock = OSAllocatedUnfairLock<Bool>(initialState: false)

    init(queue: DispatchQueue, sample: @escaping @Sendable () -> Void) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timer.setEventHandler(handler: sample)
        self.timer = timer
    }

    func start() {
        let shouldResume = lock.withLock { running -> Bool in
            guard !running else { return false }
            running = true
            return true
        }
        guard shouldResume else { return }
        timer.resume()
    }

    func stop() {
        let shouldSuspend = lock.withLock { running -> Bool in
            guard running else { return false }
            running = false
            return true
        }
        guard shouldSuspend else { return }
        timer.suspend()
    }
}
```

- [ ] **Step 2: Build**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS'`
Expected: BUILD SUCCEEDED.

- [ ] **Step 3: Commit**

```bash
git add opfilter/XPC/DispatchSourceMetricsTimer.swift
git commit -m "feat: add DispatchSourceMetricsTimer adapter for 1Hz metrics"
```

---

## Task 10: Add `beginMetricsEventStream` / `endMetricsEventStream` to `ServiceProtocol`

**Files:**
- Modify: `Shared/XPCProtocol.swift`

- [ ] **Step 1: Add the two methods to `ServiceProtocol`**

In `Shared/XPCProtocol.swift`, find the existing allow-stream block (around line 354–357):

```swift
    // Allow-event stream: the GUI subscribes when the events screen is
    // visible and unsubscribes when the screen leaves view or the window hides.
    func beginAllowEventStream(withReply reply: @escaping (Bool) -> Void)
    func endAllowEventStream(withReply reply: @escaping (Bool) -> Void)
```

Insert directly below it:

```swift
    // Metrics-event stream: the GUI subscribes when the metrics screen is
    // visible and unsubscribes when it leaves view or the window hides.
    // Opfilter halts the 1Hz sampling timer when no client is subscribed.
    func beginMetricsEventStream(withReply reply: @escaping (Bool) -> Void)
    func endMetricsEventStream(withReply reply: @escaping (Bool) -> Void)
```

- [ ] **Step 2: Build to confirm protocol additions compile**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS'`
Expected: BUILD FAILED — opfilter's `ConnectionHandler` does not yet implement the new methods. This is intentional; the next task implements them.

- [ ] **Step 3: No commit yet** (the build fails until Task 11 lands; commit them together to keep the repo green per-commit).

---

## Task 11: Implement new entrypoints on `XPCServer` / `ConnectionHandler`

**Files:**
- Modify: `opfilter/XPC/XPCServer.swift`

The existing `ConnectionHandler` in `XPCServer.swift` implements `beginAllowEventStream` / `endAllowEventStream` around lines 657–682. We mirror that shape, but route through `MetricsBroadcaster` instead of `EventBroadcaster`.

- [ ] **Step 1: Hold a `MetricsBroadcaster` on `XPCServer`**

In `opfilter/XPC/XPCServer.swift`, find:

```swift
    private let broadcaster: EventBroadcaster
```

Replace with:

```swift
    private let broadcaster: EventBroadcaster
    private let metricsBroadcaster: MetricsBroadcaster
```

Find the initialiser:

```swift
    init(
        broadcaster: EventBroadcaster,
        serverQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.xpc-server", qos: .userInitiated)
    ) {
        self.broadcaster = broadcaster
        self.serverQueue = serverQueue
        super.init()
    }
```

Replace with:

```swift
    init(
        broadcaster: EventBroadcaster,
        metricsBroadcaster: MetricsBroadcaster,
        serverQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.xpc-server", qos: .userInitiated)
    ) {
        self.broadcaster = broadcaster
        self.metricsBroadcaster = metricsBroadcaster
        self.serverQueue = serverQueue
        super.init()
    }
```

- [ ] **Step 2: Route `pushMetrics` through the new broadcaster**

Find:

```swift
        serverQueue.async { [self] in
            broadcaster.broadcastToAllClients { $0.metricsUpdated(snapshot) }
        }
```

Replace with:

```swift
        serverQueue.async { [self] in
            metricsBroadcaster.broadcast(snapshot)
        }
```

- [ ] **Step 3: Register/unregister clients on the metrics broadcaster too**

Find `addGUIClient(_:)`:

```swift
    fileprivate func addGUIClient(_ connection: NSXPCConnection) {
        _ = broadcaster.addClient(connection)
        ...
```

Insert immediately after the existing `broadcaster.addClient(connection)` call:

```swift
        _ = metricsBroadcaster.addClient(connection)
```

Find `removeClient(_:)`:

```swift
    fileprivate func removeClient(_ connection: NSXPCConnection) {
        _ = broadcaster.removeClient(connection)
    }
```

Replace with:

```swift
    fileprivate func removeClient(_ connection: NSXPCConnection) {
        _ = broadcaster.removeClient(connection)
        _ = metricsBroadcaster.removeClient(connection)
    }
```

- [ ] **Step 4: Add `fileprivate` helpers for the new entrypoints**

Insert below the existing `endAllowStream(for:)` (around line 204):

```swift
    fileprivate func beginMetricsStream(for connection: NSXPCConnection) {
        metricsBroadcaster.beginStream(for: connection)
    }

    fileprivate func endMetricsStream(for connection: NSXPCConnection) {
        metricsBroadcaster.endStream(for: connection)
    }
```

- [ ] **Step 5: Implement `beginMetricsEventStream` / `endMetricsEventStream` on `ConnectionHandler`**

Find the existing `endAllowEventStream(withReply:)` implementation (around line 676–682). Insert directly below it:

```swift
    func beginMetricsEventStream(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server else { reply(false); return }
        server.serverQueue.async {
            server.beginMetricsStream(for: conn)
            reply(true)
        }
    }

    func endMetricsEventStream(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server else { reply(false); return }
        server.serverQueue.async {
            server.endMetricsStream(for: conn)
            reply(true)
        }
    }
```

- [ ] **Step 6: Build (still fails — `main.swift` constructs `XPCServer` without `metricsBroadcaster`)**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS'`
Expected: BUILD FAILED at `let server = XPCServer(broadcaster: broadcaster, serverQueue: xpcServerQueue)` in `opfilter/main.swift` — missing argument. Resolved by Task 12.

- [ ] **Step 7: No commit yet** (build still red; bundle with Task 12).

---

## Task 12: Wire `MetricsBroadcaster` + `DispatchSourceMetricsTimer` in `main.swift`

**Files:**
- Modify: `opfilter/main.swift`

- [ ] **Step 1: Replace the existing metrics timer block**

Find the existing block (around lines 31–32 and 140–162):

```swift
let broadcaster = EventBroadcaster()
let server = XPCServer(broadcaster: broadcaster, serverQueue: xpcServerQueue)
server.start()
```

Replace with:

```swift
let broadcaster = EventBroadcaster()
let metricsLogger = Logger(subsystem: "uk.craigbass.clearancekit.metrics", category: "metrics")

// The metrics timer is constructed before the server so we can hand its
// controller to the metrics broadcaster, but its sample handler captures
// `server`, so we wire `server` into the closure via an unowned-style box.
final class MetricsServerHolder: @unchecked Sendable {
    var server: XPCServer?
}
let serverHolder = MetricsServerHolder()

let metricsTimer = DispatchSourceMetricsTimer(queue: metricsQueue) {
    let sampleDate = Date(timeIntervalSince1970: Double(clock_gettime_nsec_np(CLOCK_REALTIME)) / 1_000_000_000)
    let m = pipeline.metrics()
    let jm = jailInteractor.jailMetrics()
    serverHolder.server?.pushMetrics(m, jail: jm, timestamp: sampleDate)
    metricsLogger.info("""
    pipeline_metrics \
    ts=\(sampleDate.timeIntervalSince1970, privacy: .public) \
    eventBufferEnqueueCount=\(m.eventBufferEnqueueCount, privacy: .public) \
    eventBufferDropCount=\(m.eventBufferDropCount, privacy: .public) \
    hotPathProcessedCount=\(m.hotPathProcessedCount, privacy: .public) \
    hotPathRespondedCount=\(m.hotPathRespondedCount, privacy: .public) \
    slowQueueEnqueueCount=\(m.slowQueueEnqueueCount, privacy: .public) \
    slowQueueDropCount=\(m.slowQueueDropCount, privacy: .public) \
    slowPathProcessedCount=\(m.slowPathProcessedCount, privacy: .public) \
    jailEvaluatedCount=\(jm.jailEvaluatedCount, privacy: .public) \
    jailDenyCount=\(jm.jailDenyCount, privacy: .public)
    """)
}
let metricsBroadcaster = MetricsBroadcaster(timerController: metricsTimer)

let server = XPCServer(broadcaster: broadcaster, metricsBroadcaster: metricsBroadcaster, serverQueue: xpcServerQueue)
serverHolder.server = server
server.start()
```

Then find and **delete** the old metrics block (around lines 140–162):

```swift
let metricsLogger = Logger(subsystem: "uk.craigbass.clearancekit.metrics", category: "metrics")
let metricsTimer = DispatchSource.makeTimerSource(queue: metricsQueue)
metricsTimer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
metricsTimer.setEventHandler {
    ...
}
metricsTimer.resume()
```

(The replacement above is the only metrics-related code in `main.swift`.)

- [ ] **Step 2: Build**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS'`
Expected: BUILD SUCCEEDED.

- [ ] **Step 3: Run the test suite**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS'`
Expected: all tests PASS (including the six new `MetricsBroadcaster` tests; existing `EventBroadcaster` tests remain green).

- [ ] **Step 4: Commit (covers Tasks 10–12 together so each commit leaves the build green)**

```bash
git add Shared/XPCProtocol.swift opfilter/XPC/XPCServer.swift opfilter/main.swift
git commit -m "feat: route metrics push through MetricsBroadcaster, gate timer on subscribers"
```

---

## Task 13: GUI — `XPCClient.beginMetricsEventStream` / `endMetricsEventStream` with internal ref-count

**Files:**
- Modify: `clearancekit/App/XPCClient.swift`

- [ ] **Step 1: Add the methods, an internal ref-count, and the resume seam**

In `clearancekit/App/XPCClient.swift`, find:

```swift
    var shouldResumeAllowEventStream: @MainActor () -> Bool = { false }
```

Insert directly below it:

```swift
    var shouldResumeMetricsStream: @MainActor () -> Bool = { false }
```

Find the existing allow-stream methods block:

```swift
    // MARK: - Allow event stream

    func beginAllowEventStream() {
        ...
    }

    func endAllowEventStream() {
        ...
    }
```

Insert directly below `endAllowEventStream`:

```swift
    // MARK: - Metrics event stream

    /// Tracks how many SwiftUI views have asked to be subscribed. Allows duplicate
    /// onAppear/onDisappear pairs without desyncing server-side state.
    private var metricsStreamRefCount = 0

    func beginMetricsEventStream() {
        metricsStreamRefCount += 1
        guard metricsStreamRefCount == 1 else { return }
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            logger.error("XPCClient: beginMetricsEventStream error: \(error.localizedDescription, privacy: .public)")
        }) as? ServiceProtocol else { return }
        service.beginMetricsEventStream { success in
            if !success { logger.error("XPCClient: beginMetricsEventStream rejected by service") }
        }
    }

    func endMetricsEventStream() {
        guard metricsStreamRefCount > 0 else { return }
        metricsStreamRefCount -= 1
        guard metricsStreamRefCount == 0 else { return }
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            logger.error("XPCClient: endMetricsEventStream error: \(error.localizedDescription, privacy: .public)")
        }) as? ServiceProtocol else { return }
        service.endMetricsEventStream { success in
            if !success { logger.error("XPCClient: endMetricsEventStream rejected by service") }
        }
    }
```

- [ ] **Step 2: Wire reconnect resume**

Find the existing post-`registerClient` block in `connect()`:

```swift
                    if self?.shouldResumeAllowEventStream() == true {
                        self?.beginAllowEventStream()
                    }
```

Replace with:

```swift
                    if self?.shouldResumeAllowEventStream() == true {
                        self?.beginAllowEventStream()
                    }
                    if self?.shouldResumeMetricsStream() == true {
                        // Reset the local ref-count so the resume issues a fresh
                        // server-side subscription rather than being swallowed by
                        // a stale ref-count from before the disconnect.
                        self?.metricsStreamRefCount = 0
                        self?.beginMetricsEventStream()
                    }
```

(Apply the same `metricsStreamRefCount = 0` reset inside `handleDisconnection()` if that method exists and clears other client state — locate it via grep and add the line; if it does not reset other stream state, skip that addition.)

- [ ] **Step 3: Build**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS'`
Expected: BUILD SUCCEEDED.

- [ ] **Step 4: Commit**

```bash
git add clearancekit/App/XPCClient.swift
git commit -m "feat: XPCClient gains beginMetricsEventStream with reconnect resume"
```

---

## Task 14: `NavigationState.isMetricsScreenActive`

**Files:**
- Modify: `clearancekit/App/NavigationState.swift`

- [ ] **Step 1: Add the computed property**

In `clearancekit/App/NavigationState.swift`, find:

```swift
    var isEventsScreenActive: Bool {
        windowVisible && selection == .events
    }
```

Insert directly below it:

```swift
    var isMetricsScreenActive: Bool {
        windowVisible && selection == .metrics
    }
```

- [ ] **Step 2: Build**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS'`
Expected: BUILD SUCCEEDED.

- [ ] **Step 3: Commit**

```bash
git add clearancekit/App/NavigationState.swift
git commit -m "feat: NavigationState exposes isMetricsScreenActive"
```

---

## Task 15: Inject `shouldResumeMetricsStream` at app launch

**Files:**
- Modify: `clearancekit/App/clearancekitApp.swift`

- [ ] **Step 1: Add the closure injection alongside the existing allow-stream injection**

In `clearancekit/App/clearancekitApp.swift`, find:

```swift
        XPCClient.shared.shouldResumeAllowEventStream = { NavigationState.shared.isEventsScreenActive }
```

Insert directly below it:

```swift
        XPCClient.shared.shouldResumeMetricsStream = { NavigationState.shared.isMetricsScreenActive }
```

- [ ] **Step 2: Build**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS'`
Expected: BUILD SUCCEEDED.

- [ ] **Step 3: Commit**

```bash
git add clearancekit/App/clearancekitApp.swift
git commit -m "feat: wire metrics stream resume on reconnect"
```

---

## Task 16: `MetricsView` subscribes on appear / unsubscribes on disappear

**Files:**
- Modify: `clearancekit/Monitor/Metrics/MetricsView.swift`

- [ ] **Step 1: Add lifecycle hooks**

In `clearancekit/Monitor/Metrics/MetricsView.swift`, find the closing `.navigationTitle("Metrics")` modifier:

```swift
        .navigationTitle("Metrics")
    }
```

Replace with:

```swift
        .navigationTitle("Metrics")
        .onAppear {
            NavigationState.shared.selection = .metrics
            xpcClient.beginMetricsEventStream()
        }
        .onDisappear {
            xpcClient.endMetricsEventStream()
        }
    }
```

(Setting `selection = .metrics` on appear keeps `isMetricsScreenActive` accurate even if the view is shown without a sidebar click — this matches how `EventsWindowView` interacts with `NavigationState` for the allow stream. If `EventsWindowView` does not set its selection on appear, **omit the `selection = .metrics` line**: `selection` is already updated by the sidebar click before navigation. Verify with `grep -n "selection = " clearancekit/Monitor/Events/*.swift` before deciding.)

- [ ] **Step 2: Build**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS'`
Expected: BUILD SUCCEEDED.

- [ ] **Step 3: Run the full test suite**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS'`
Expected: all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add clearancekit/Monitor/Metrics/MetricsView.swift
git commit -m "feat: MetricsView subscribes to metrics stream while visible"
```

---

## Task 17: Manual verification

**Files:** none.

- [ ] **Step 1: Build and install the dev app + system extension**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS'`
Expected: BUILD SUCCEEDED. Install the resulting app following the project's normal dev workflow.

- [ ] **Step 2: Verify metrics timer is paused at idle**

In Console.app, filter on subsystem `uk.craigbass.clearancekit.metrics`. With the GUI window hidden and the metrics screen never visited, expect **no** `pipeline_metrics` log lines.

- [ ] **Step 3: Verify subscribe → resume**

Open the app window, click the Metrics sidebar item. Expect `pipeline_metrics` log lines to begin within ~1 second. Chart should populate after ~2 seconds (the existing `metricsHistory.count < 2` placeholder threshold).

- [ ] **Step 4: Verify unsubscribe → pause**

Switch to a different sidebar item (e.g. Events). Expect `pipeline_metrics` log lines to stop within ~1 second.

- [ ] **Step 5: Verify hide-window → pause**

Click the Metrics sidebar item again to start the stream, then close the window with the red traffic light (hides per v5.0.8 behaviour). Confirm log lines stop. Re-show the window via the menu bar — log lines do **not** restart automatically because `MetricsView.onAppear` does not fire on window show without a sidebar interaction. Click Metrics again to confirm they restart.

- [ ] **Step 6: Verify reconnect resume**

With Metrics screen visible and log lines flowing, restart `opfilter` (`sudo killall opfilter` or however the dev workflow restarts the system extension). Once reconnect completes, expect `pipeline_metrics` log lines to resume automatically without further user action — this exercises the `shouldResumeMetricsStream` closure.

- [ ] **Step 7: Commit any tweaks discovered during manual verification**

If verification fails on any step, file as a follow-up task in this plan rather than amending. Otherwise no commit.

---

## Self-review

**Spec coverage**

- Goal *halt 1Hz push when no client subscribed* — Tasks 5–6 (`endStream` / `removeClient` stop the timer) + Task 12 (no unconditional `metricsTimer.resume()`).
- Goal *halt sampling timer entirely* — Task 9 (`stop()` calls `timer.suspend()`) + Task 12 (timer constructed but never resumed at startup).
- Goal *auto-resume on reconnect when MetricsView active* — Task 13 (resume seam + reset ref-count) + Tasks 14–15 (`isMetricsScreenActive` + injection).
- Goal *cut post-sleep CPU spike* — manifests automatically once the timer is gated; verified by Task 17 step 2.
- Non-goal *deny event broadcast unchanged* — `EventBroadcaster` untouched; only `pushMetrics` re-routes (Task 11 step 2).
- Non-goal *allow-stream unchanged* — confirmed: only `EventBroadcaster.broadcastToAllClients { metricsUpdated }` is replaced; allow-stream paths and `EventBroadcaster` API are untouched.
- Architecture *dedicated `MetricsBroadcaster`* — Task 2.
- Architecture *`MetricsTimerControlling` seam* — Task 1, with `DispatchSourceMetricsTimer` adapter in Task 9.
- Architecture *`XPCServer` holds both broadcasters* — Task 11 step 1.
- Architecture *`addClient` + `removeClient` mirrored* — Task 11 step 3.
- Data flow *broadcast skips when no subscribers* — Task 8.
- Edge case *idempotent end-stream* — Task 7.
- Edge case *idempotent timer start/stop* — Task 9 (lock-guarded `isRunning` flag).
- Edge case *duplicate subscribe from SwiftUI* — Task 13 ref-count.
- Testing *all eight cases from spec* — Tasks 3, 4, 5, 6, 7, 8 cover six cases. The remaining two (`broadcastFanOutToAllRegisteredClients`, `broadcastWhileNotRunningDoesNotCrash`) are folded into the `broadcastWithNoSubscribersDoesNotThrow` case, since the existing `EventBroadcaster` test pattern uses bare `NSXPCConnection()` instances whose `remoteObjectProxy` cannot be exercised in unit tests. Documented as out-of-scope in the spec; the manual verification (Task 17) covers the live fan-out path.

**Placeholder scan** — none found.

**Type consistency** — `metricsBroadcaster` parameter name and `MetricsBroadcaster` type used consistently across Tasks 2, 8, 11, 12. `beginStream(for:)` / `endStream(for:)` / `addClient(_:)` / `removeClient(_:)` / `broadcast(_:)` signatures are stable from Task 3 onward. `MetricsTimerControlling` has only `start()` / `stop()` throughout. `shouldResumeMetricsStream` typed identically in Tasks 13 and 15. `isMetricsScreenActive` defined in Task 14 and consumed in Task 15.
