# Event Streaming & Window Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make allow-event streaming on-demand (only when the events screen is visible) and fix window/dock lifecycle so dock icon appears only when a window is open.

**Architecture:** Two independent workstreams sharing one integration point (window hide triggers `endAllowEventStream`). Workstream 1 adds `beginAllowEventStream`/`endAllowEventStream` to the XPC protocol and filters allow events in EventBroadcaster. Workstream 2 intercepts window close to hide instead of destroy, toggles `NSApp.setActivationPolicy()` between `.regular` and `.accessory`, and tracks window visibility.

**Tech Stack:** Swift, SwiftUI, NSXPCConnection, Endpoint Security (opfilter), Swift Testing

---

### Task 1: Add Allow-Stream Subscription State to EventBroadcaster

**Files:**
- Modify: `opfilter/XPC/EventBroadcaster.swift:17-22` (State struct)
- Modify: `opfilter/XPC/EventBroadcaster.swift:44-50` (removeClient)
- Test: `Tests/EventBroadcasterTests.swift`

- [ ] **Step 1: Write failing test — beginAllowStream adds connection to subscribers**

Add to `Tests/EventBroadcasterTests.swift`:

```swift
// MARK: - Allow stream subscription

@Test("beginAllowStream tracks subscribing connection")
func beginAllowStreamTracksConnection() {
    let broadcaster = EventBroadcaster()
    let conn = NSXPCConnection()
    broadcaster.addClient(conn)

    broadcaster.beginAllowStream(for: conn)

    #expect(broadcaster.allowStreamClientCount == 1)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:'clearancekitTests/EventBroadcasterTests/beginAllowStreamTracksConnection' 2>&1 | tail -20`
Expected: compilation error — `beginAllowStream` and `allowStreamClientCount` don't exist

- [ ] **Step 3: Write minimal implementation**

In `opfilter/XPC/EventBroadcaster.swift`, add `allowStreamClients` to the State struct:

```swift
private struct State {
    var guiClients: [ObjectIdentifier: NSXPCConnection] = [:]
    var allowStreamClients: Set<ObjectIdentifier> = []
    var recentEvents: [FolderOpenEvent] = []
    var recentTamperEvents: [TamperAttemptEvent] = []
}
```

Add methods after the `removeClient` method:

```swift
// MARK: - Allow-event stream subscription

func beginAllowStream(for connection: NSXPCConnection) {
    storage.withLock { state in
        state.allowStreamClients.insert(ObjectIdentifier(connection))
    }
}

func endAllowStream(for connection: NSXPCConnection) {
    storage.withLock { state in
        state.allowStreamClients.remove(ObjectIdentifier(connection))
    }
}

var allowStreamClientCount: Int {
    storage.withLock { $0.allowStreamClients.count }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:'clearancekitTests/EventBroadcasterTests/beginAllowStreamTracksConnection' 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 5: Write failing test — endAllowStream removes connection**

```swift
@Test("endAllowStream removes subscribing connection")
func endAllowStreamRemovesConnection() {
    let broadcaster = EventBroadcaster()
    let conn = NSXPCConnection()
    broadcaster.addClient(conn)
    broadcaster.beginAllowStream(for: conn)

    broadcaster.endAllowStream(for: conn)

    #expect(broadcaster.allowStreamClientCount == 0)
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:'clearancekitTests/EventBroadcasterTests/endAllowStreamRemovesConnection' 2>&1 | tail -20`
Expected: PASS (already implemented)

- [ ] **Step 7: Write failing test — removeClient cleans up allow stream subscription**

```swift
@Test("removeClient also removes from allow stream subscribers")
func removeClientCleansUpAllowStream() {
    let broadcaster = EventBroadcaster()
    let conn = NSXPCConnection()
    broadcaster.addClient(conn)
    broadcaster.beginAllowStream(for: conn)

    broadcaster.removeClient(conn)

    #expect(broadcaster.allowStreamClientCount == 0)
}
```

- [ ] **Step 8: Run test to verify it fails**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:'clearancekitTests/EventBroadcasterTests/removeClientCleansUpAllowStream' 2>&1 | tail -20`
Expected: FAIL — `allowStreamClientCount` is still 1

- [ ] **Step 9: Update removeClient to clean up allow stream**

In `opfilter/XPC/EventBroadcaster.swift`, modify `removeClient`:

```swift
@discardableResult
func removeClient(_ connection: NSXPCConnection) -> Int {
    storage.withLock { state in
        let id = ObjectIdentifier(connection)
        state.guiClients.removeValue(forKey: id)
        state.allowStreamClients.remove(id)
        return state.guiClients.count
    }
}
```

- [ ] **Step 10: Run test to verify it passes**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:'clearancekitTests/EventBroadcasterTests/removeClientCleansUpAllowStream' 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 11: Run all EventBroadcaster tests**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:'clearancekitTests/EventBroadcasterTests' 2>&1 | tail -30`
Expected: All pass

- [ ] **Step 12: Commit**

```bash
git add opfilter/XPC/EventBroadcaster.swift Tests/EventBroadcasterTests.swift
git commit -m "feat: add allow-stream subscription state to EventBroadcaster"
```

---

### Task 2: Filter Allow Events in broadcast()

**Files:**
- Modify: `opfilter/XPC/EventBroadcaster.swift:55-66` (broadcast FolderOpenEvent)
- Test: `Tests/EventBroadcasterTests.swift`

This task requires verifying that allow events are only sent to subscribed clients. Since EventBroadcaster calls `remoteObjectProxy` on `NSXPCConnection` (which returns nil in test context), we test the observable effect: the ring buffer behavior (all events stored regardless) and the filtering logic indirectly via the subscription state.

The key behavioral change is in the `broadcast` method. We can't easily verify XPC delivery in unit tests, but we can verify the ring buffer still stores all events and the subscription tracking works correctly.

- [ ] **Step 1: Write failing test — allow events still stored in ring buffer regardless of subscribers**

```swift
@Test("allow events are stored in ring buffer even without subscribers")
func allowEventsStoredInRingBufferWithoutSubscribers() {
    let broadcaster = EventBroadcaster()
    let event = FolderOpenEvent(
        path: "/test",
        timestamp: Date(),
        processID: 100,
        processPath: "/usr/bin/test",
        accessAllowed: true
    )

    broadcaster.broadcast(event)

    #expect(broadcaster.recentEvents().count == 1)
    #expect(broadcaster.recentEvents()[0].eventID == event.eventID)
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:'clearancekitTests/EventBroadcasterTests/allowEventsStoredInRingBufferWithoutSubscribers' 2>&1 | tail -20`
Expected: PASS (ring buffer behavior unchanged)

- [ ] **Step 3: Modify broadcast to filter allow events**

In `opfilter/XPC/EventBroadcaster.swift`, replace the `broadcast(_ event: FolderOpenEvent)` method:

```swift
func broadcast(_ event: FolderOpenEvent) {
    let (denyClients, allowClients) = storage.withLock { state -> ([NSXPCConnection], [NSXPCConnection]) in
        state.recentEvents.append(event)
        if state.recentEvents.count > maxHistoryCount {
            state.recentEvents.removeFirst(state.recentEvents.count - maxHistoryCount)
        }
        let allClients = Array(state.guiClients.values)
        guard event.accessAllowed else {
            return (allClients, [])
        }
        let subscribed = allClients.filter { state.allowStreamClients.contains(ObjectIdentifier($0)) }
        return ([], subscribed)
    }
    for conn in denyClients {
        (conn.remoteObjectProxy as? ClientProtocol)?.folderOpened(event)
    }
    for conn in allowClients {
        (conn.remoteObjectProxy as? ClientProtocol)?.folderOpened(event)
    }
}
```

- [ ] **Step 4: Run all EventBroadcaster tests**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:'clearancekitTests/EventBroadcasterTests' 2>&1 | tail -30`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add opfilter/XPC/EventBroadcaster.swift Tests/EventBroadcasterTests.swift
git commit -m "feat: filter allow events to only subscribed clients in EventBroadcaster"
```

---

### Task 3: Add Backfill to beginAllowStream

**Files:**
- Modify: `opfilter/XPC/EventBroadcaster.swift` (beginAllowStream method)
- Test: `Tests/EventBroadcasterTests.swift`

- [ ] **Step 1: Write failing test — beginAllowStream returns allow-only backfill newest-first**

```swift
@Test("beginAllowStream returns allow-only events from ring buffer newest-first")
func beginAllowStreamReturnsBackfill() {
    let broadcaster = EventBroadcaster()
    let conn = NSXPCConnection()
    broadcaster.addClient(conn)

    let deny = FolderOpenEvent(path: "/deny", timestamp: Date(timeIntervalSince1970: 1), processID: 1, processPath: "/p", accessAllowed: false)
    let allowOld = FolderOpenEvent(path: "/old", timestamp: Date(timeIntervalSince1970: 2), processID: 2, processPath: "/p", accessAllowed: true)
    let allowNew = FolderOpenEvent(path: "/new", timestamp: Date(timeIntervalSince1970: 3), processID: 3, processPath: "/p", accessAllowed: true)

    broadcaster.broadcast(deny)
    broadcaster.broadcast(allowOld)
    broadcaster.broadcast(allowNew)

    let backfill = broadcaster.beginAllowStream(for: conn)

    #expect(backfill.count == 2)
    #expect(backfill[0].eventID == allowNew.eventID)
    #expect(backfill[1].eventID == allowOld.eventID)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:'clearancekitTests/EventBroadcasterTests/beginAllowStreamReturnsBackfill' 2>&1 | tail -20`
Expected: compilation error — `beginAllowStream` returns Void, not `[FolderOpenEvent]`

- [ ] **Step 3: Update beginAllowStream to return backfill**

In `opfilter/XPC/EventBroadcaster.swift`, replace `beginAllowStream`:

```swift
@discardableResult
func beginAllowStream(for connection: NSXPCConnection) -> [FolderOpenEvent] {
    storage.withLock { state in
        state.allowStreamClients.insert(ObjectIdentifier(connection))
        return state.recentEvents.filter(\.accessAllowed).reversed()
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:'clearancekitTests/EventBroadcasterTests/beginAllowStreamReturnsBackfill' 2>&1 | tail -20`
Expected: PASS

- [ ] **Step 5: Run all EventBroadcaster tests**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:'clearancekitTests/EventBroadcasterTests' 2>&1 | tail -30`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add opfilter/XPC/EventBroadcaster.swift Tests/EventBroadcasterTests.swift
git commit -m "feat: return allow-event backfill from beginAllowStream"
```

---

### Task 4: Add XPC Protocol Methods and Wire Server

**Files:**
- Modify: `Shared/XPCProtocol.swift:304-374` (ServiceProtocol)
- Modify: `opfilter/XPC/XPCServer.swift:179-205` (client management section)
- Modify: `opfilter/XPC/XPCServer.swift:480-704` (ConnectionHandler)

- [ ] **Step 1: Add protocol methods to ServiceProtocol**

In `Shared/XPCProtocol.swift`, add after the `endDiscovery` declaration (line 352):

```swift
// Allow-event stream: the GUI subscribes when the events screen is
// visible and unsubscribes when the screen leaves view or the window hides.
func beginAllowEventStream(withReply reply: @escaping (Bool) -> Void)
func endAllowEventStream(withReply reply: @escaping (Bool) -> Void)
```

- [ ] **Step 2: Add server-side methods to XPCServer**

In `opfilter/XPC/XPCServer.swift`, add after the `removeClient` method (after line 196):

```swift
fileprivate func beginAllowStream(for connection: NSXPCConnection) -> [FolderOpenEvent] {
    broadcaster.beginAllowStream(for: connection)
}

fileprivate func endAllowStream(for connection: NSXPCConnection) {
    broadcaster.endAllowStream(for: connection)
}
```

- [ ] **Step 3: Add ConnectionHandler implementations**

In `opfilter/XPC/XPCServer.swift`, add to `ConnectionHandler` after the `endDiscovery` method:

```swift
func beginAllowEventStream(withReply reply: @escaping (Bool) -> Void) {
    guard let conn = connection, let server else { reply(false); return }
    server.serverQueue.async {
        let backfill = server.beginAllowStream(for: conn)
        guard let proxy = conn.remoteObjectProxy as? ClientProtocol else {
            reply(true)
            return
        }
        let batchSize = 50
        for batchStart in stride(from: 0, to: backfill.count, by: batchSize) {
            let batchEnd = min(batchStart + batchSize, backfill.count)
            for event in backfill[batchStart..<batchEnd] {
                proxy.folderOpened(event)
            }
        }
        reply(true)
    }
}

func endAllowEventStream(withReply reply: @escaping (Bool) -> Void) {
    guard let conn = connection, let server else { reply(false); return }
    server.serverQueue.async {
        server.endAllowStream(for: conn)
        reply(true)
    }
}
```

- [ ] **Step 4: Build to verify compilation**

Run: `xcodebuild build -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | tail -20`
Expected: BUILD SUCCEEDED

- [ ] **Step 5: Run all tests**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | tail -30`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add Shared/XPCProtocol.swift opfilter/XPC/XPCServer.swift
git commit -m "feat: add beginAllowEventStream/endAllowEventStream XPC methods"
```

---

### Task 5: Wire Client-Side Allow Stream Calls

**Files:**
- Modify: `clearancekit/App/XPCClient.swift` (add begin/end methods)
- Modify: `clearancekit/App/NavigationState.swift` (add window visibility tracking)
- Modify: `clearancekit/Monitor/Events/EventsWindowView.swift:41-43` (onAppear/onDisappear)

- [ ] **Step 1: Add allow stream methods to XPCClient**

In `clearancekit/App/XPCClient.swift`, add after the `endDiscovery` method (after line 464):

```swift
// MARK: - Allow event stream

func beginAllowEventStream() {
    guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
        logger.error("XPCClient: beginAllowEventStream error: \(error.localizedDescription, privacy: .public)")
    }) as? ServiceProtocol else { return }
    service.beginAllowEventStream { success in
        if !success { logger.error("XPCClient: beginAllowEventStream rejected by service") }
    }
}

func endAllowEventStream() {
    guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
        logger.error("XPCClient: endAllowEventStream error: \(error.localizedDescription, privacy: .public)")
    }) as? ServiceProtocol else { return }
    service.endAllowEventStream { success in
        if !success { logger.error("XPCClient: endAllowEventStream rejected by service") }
    }
}
```

- [ ] **Step 2: Add window visibility to NavigationState**

In `clearancekit/App/NavigationState.swift`, add a published property and update method:

```swift
@MainActor
final class NavigationState: ObservableObject {
    static let shared = NavigationState()

    @Published var selection: SidebarItem = .events
    @Published var highlightedEventID: UUID? = nil
    @Published var windowVisible = false

    private init() {}

    func navigate(toEventID eventID: UUID) {
        selection = .events
        highlightedEventID = eventID
    }

    var isEventsScreenActive: Bool {
        windowVisible && selection == .events
    }
}
```

- [ ] **Step 3: Update EventsWindowView to subscribe/unsubscribe**

In `clearancekit/Monitor/Events/EventsWindowView.swift`, replace the `.onAppear` block and add `.onDisappear` and `.onChange`:

`EventsWindowView` appears/disappears based on sidebar selection via the `switch nav.selection` in `ContentView`. So `onAppear`/`onDisappear` on the view body fires at the right times (when navigating to/from events). This handles sidebar navigation. Window hide is handled separately in Task 7.

- [ ] **Step 3: Replace fetchHistoricEvents with allow stream subscription in EventsWindowView**

The `onAppear` currently calls `xpcClient.fetchHistoricEvents()` (line 42-43). Replace it — the backfill from `beginAllowEventStream` now serves this purpose for allow events, and deny events stream continuously.

In `clearancekit/Monitor/Events/EventsWindowView.swift`, update the `.onAppear` and add `.onDisappear`:

```swift
.onAppear {
    xpcClient.beginAllowEventStream()
}
.onDisappear {
    xpcClient.endAllowEventStream()
}
```

- [ ] **Step 5: Build to verify compilation**

Run: `xcodebuild build -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | tail -20`
Expected: BUILD SUCCEEDED

- [ ] **Step 6: Commit**

```bash
git add clearancekit/App/XPCClient.swift clearancekit/App/NavigationState.swift clearancekit/Monitor/Events/EventsWindowView.swift
git commit -m "feat: wire client-side allow event stream subscribe/unsubscribe"
```

---

### Task 6: Window Close Interception and Dock Management

**Files:**
- Modify: `clearancekit/App/clearancekitApp.swift` (AppDelegate + showWindow/hideWindow)
- Modify: `clearancekit/App/NavigationState.swift` (windowVisible)

- [ ] **Step 1: Add WindowAccessor to intercept close**

Create an NSViewRepresentable that intercepts `windowWillClose` so we can hide instead of destroy. In `clearancekit/App/clearancekitApp.swift`, add before the `clearancekitApp` struct:

```swift
private struct WindowAccessor: NSViewRepresentable {
    let onClose: () -> Void

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            guard let window = view.window else { return }
            window.delegate = context.coordinator
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onClose: onClose)
    }

    final class Coordinator: NSObject, NSWindowDelegate {
        let onClose: () -> Void

        init(onClose: @escaping () -> Void) {
            self.onClose = onClose
        }

        func windowShouldClose(_ sender: NSWindow) -> Bool {
            onClose()
            return false
        }
    }
}
```

- [ ] **Step 2: Update AppDelegate to prevent termination on last window close and start as accessory**

In `clearancekit/App/clearancekitApp.swift`, add to `AppDelegate`:

```swift
func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    false
}
```

The `applicationDidFinishLaunching` already sets `.accessory` — no change needed there.

- [ ] **Step 3: Add hideWindow and update showWindow with activation policy toggling**

In `clearancekit/App/clearancekitApp.swift`, replace the `showWindow` method and add `hideWindow`:

```swift
private func showWindow() {
    NSApp.setActivationPolicy(.regular)
    openWindow(id: "main")
    NSApp.activate()
    NavigationState.shared.windowVisible = true
}

private func hideWindow() {
    NavigationState.shared.windowVisible = false
    if NavigationState.shared.isEventsScreenActive {
        XPCClient.shared.endAllowEventStream()
    }
    NSApp.keyWindow?.orderOut(nil)
    DispatchQueue.main.async {
        NSApp.setActivationPolicy(.accessory)
    }
}
```

- [ ] **Step 4: Add WindowAccessor to the Window scene**

In the `body` of `clearancekitApp`, update the Window scene to include the accessor:

```swift
Window("clearancekit", id: "main") {
    ContentView()
        .background(WindowAccessor(onClose: { [self] in
            hideWindow()
        }))
}
```

Note: The `[self]` capture is needed because `clearancekitApp` is a struct.

- [ ] **Step 5: Build to verify compilation**

Run: `xcodebuild build -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | tail -20`
Expected: BUILD SUCCEEDED

- [ ] **Step 6: Commit**

```bash
git add clearancekit/App/clearancekitApp.swift clearancekit/App/NavigationState.swift
git commit -m "feat: intercept window close to hide, toggle dock icon via activation policy"
```

---

### Task 7: Integration — Wire Window Visibility to Allow Stream

**Files:**
- Modify: `clearancekit/App/clearancekitApp.swift` (launch behavior)
- Modify: `clearancekit/App/XPCClient.swift` (reconnect triggers re-subscribe)

- [ ] **Step 1: Ensure no window shown on launch**

The app already sets `.accessory` in `applicationDidFinishLaunching` and the SwiftUI `Window` scene does not auto-show in accessory mode. Verify by building and running — the app should appear only in the menu bar.

If the window auto-shows despite accessory mode, add `.defaultLaunchBehavior(.suppressed)` to the `Window` scene (macOS 15+). For older macOS, the `WindowAccessor` approach with initial `orderOut` may be needed.

- [ ] **Step 2: Handle reconnect when events screen is visible**

In `clearancekit/App/XPCClient.swift`, in the `registerClient` success handler (around line 181-186), add re-subscription:

```swift
service.registerClient { [weak self] success in
    Task { @MainActor in
        if success {
            logger.debug("XPCClient: Successfully registered with service")
            self?.isConnected = true
            self?.hasServiceVersionMismatch = false
            self?.stopReconnectTimer()
            self?.fetchVersionInfo()
            self?.requestResync()
            if NavigationState.shared.isEventsScreenActive {
                self?.beginAllowEventStream()
            }
        } else {
            logger.error("XPCClient: Failed to register with service")
            self?.handleDisconnection()
        }
    }
}
```

- [ ] **Step 3: Ensure hideWindow calls endAllowEventStream regardless of current screen**

The `hideWindow()` method from Task 6 already calls `endAllowEventStream()` when the events screen is active. However, the window might close while on a different screen after having visited events. The `onDisappear` on `EventsWindowView` handles sidebar navigation, and `endAllowEventStream` is idempotent on the server (removing from a set that doesn't contain the connection is a no-op). So calling it unconditionally on window hide is safe and simpler.

Update `hideWindow()` in `clearancekitApp.swift`:

```swift
private func hideWindow() {
    NavigationState.shared.windowVisible = false
    XPCClient.shared.endAllowEventStream()
    NSApp.keyWindow?.orderOut(nil)
    DispatchQueue.main.async {
        NSApp.setActivationPolicy(.accessory)
    }
}
```

- [ ] **Step 4: Build and run full test suite**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | tail -30`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add clearancekit/App/clearancekitApp.swift clearancekit/App/XPCClient.swift
git commit -m "feat: integrate window visibility with allow event stream lifecycle"
```

---

### Task 8: Manual Verification

**Files:** None (testing only)

- [ ] **Step 1: Build and launch the app**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS' 2>&1 | tail -10`
Then launch the app manually.

- [ ] **Step 2: Verify launch behavior**

- App appears in menu bar only (shield icon)
- No dock icon visible
- No window visible
- Cmd+Tab does not show clearancekit

- [ ] **Step 3: Verify Show from menu bar**

- Click menu bar icon → click "Show"
- Window appears
- Dock icon appears
- App visible in Cmd+Tab

- [ ] **Step 4: Verify window close hides to menu bar**

- Click red traffic light on window
- Window hides (not destroyed)
- Dock icon disappears
- App still in menu bar

- [ ] **Step 5: Verify events screen streaming**

- Open window, navigate to Events sidebar
- Allow events should appear (backfill first, then live)
- Navigate to a different sidebar item
- Navigate back to Events — fresh backfill arrives

- [ ] **Step 6: Verify notification-triggered show**

- Close window
- Trigger a deny event (access a protected folder)
- Click the system notification
- Window should appear with events screen, scrolled to the denied event

- [ ] **Step 7: Verify signature issue show**

- If possible, trigger a signature issue
- Window should appear with the modal sheet

- [ ] **Step 8: Commit any fixes discovered during manual testing**

If any issues found, fix and commit individually with descriptive messages.
