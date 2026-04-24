# Event Streaming & Window Management Design

## Problem

Two issues with the ClearanceKit GUI:

1. **Unnecessary event streaming** — opfilter broadcasts all allow and deny events to all connected clients unconditionally. Allow events vastly outnumber denies on most systems, creating unnecessary XPC traffic when the user isn't viewing the events screen.

2. **Inconsistent window/dock management** — the app uses `.accessory` activation policy permanently, leading to states where there's no dock icon but a visible window, or a dock icon with no window. Window close behavior is unmanaged.

## Design

### 1. Allow Event Streaming — On-Demand Subscription

#### XPC Protocol Changes

Add to `ServiceProtocol`:

```swift
func beginAllowEventStream(withReply reply: @escaping (Bool) -> Void)
func endAllowEventStream(withReply reply: @escaping (Bool) -> Void)
```

Deny events continue streaming unconditionally to all clients (required for system notifications).

#### EventBroadcaster Changes

New subscription state: `allowStreamClients: Set<NSXPCConnection>` tracks which clients want allow events.

`broadcast(_ event:)` behavior change:
- Deny events → all connected clients (unchanged)
- Allow events → only connections in `allowStreamClients`

New methods:
- `beginAllowStream(for: NSXPCConnection)` — add to set, send backfill
- `endAllowStream(for: NSXPCConnection)` — remove from set
- On client disconnect: remove from `allowStreamClients`

#### Backfill on Subscribe

When a client calls `beginAllowEventStream()`:

1. Filter ring buffer to allow events only
2. Ordered newest-first
3. Send in batches of 50 via existing `folderOpened(_:)` callback
4. Client renders each batch incrementally (newest events appear first)
5. After backfill, live streaming continues seamlessly

No new callback needed — backfill uses the same `folderOpened(_:)` path.

#### Client Side (XPCClient)

`beginAllowEventStream()` called when:
- User navigates to events screen while window is visible

`endAllowEventStream()` called when:
- User navigates away from events screen (different sidebar item)
- Window closes (hides to menu bar)
- XPC disconnects

On reconnect after disconnect: re-call `beginAllowEventStream()` if events screen is still visible.

Backfilled events inserted by timestamp to maintain chronological order in the UI.

### 2. Window & Dock Management

#### Activation Policy Toggling

App launches as `.accessory` (menu bar only, no window, no dock icon).

**Show window sequence:**
1. `NSApp.setActivationPolicy(.regular)` — dock icon appears
2. `NSApp.activate()` — bring app to foreground
3. `openWindow(id: "main")` — show or create window

**Hide window sequence:**
1. Window `orderOut` — hide window first
2. `DispatchQueue.main.async { NSApp.setActivationPolicy(.accessory) }` — dock icon removed after window server processes the close

Wrapping `.accessory` in async gives the window server time to process the close, avoiding flicker.

#### Window Close Interception

Red traffic light button hides instead of destroying:
- `applicationShouldTerminateAfterLastWindowClosed` returns `false`
- Intercept window close via `NSWindowDelegate.windowWillClose` or NSViewRepresentable — trigger hide sequence instead of destroy

#### Window Visibility Tracking

New published property `windowVisible: Bool` on a coordinator. Drives:
- Activation policy toggling (`.regular` when visible, `.accessory` when hidden)
- `endAllowEventStream()` on window hide
- Menu bar "Show" button availability

#### Launch Behavior

- App starts in `.accessory` mode — menu bar icon only, no window
- "Show" in menu bar → show sequence
- Notification clicked → show sequence + navigate to denied event
- Signature issue detected → show sequence + modal sheet

#### Menu Bar

No changes to MenuBarExtra. Shield icon and status logic unchanged.

### 3. Edge Cases

**Rapid show/hide toggling:** Activation policy calls are idempotent; last one wins.

**`beginAllowEventStream` while previous backfill in-flight:** Replace subscription, restart backfill.

**Window close during backfill:** `endAllowEventStream()` sent, opfilter stops. Partial backfill is fine — client clears stale data on next subscribe.

**Disconnect during allow stream:** EventBroadcaster removes connection from `allowStreamClients` on disconnect cleanup.

### 4. What's Not Changing

- Deny event flow (always streamed)
- Tamper event flow
- Metrics streaming (1/sec)
- Rule/allowlist state sync
- Authorization request panel (separate NSPanel)
- Ring buffer size (1000 events)
- Client-side 3-second batch flush
- `fetchRecentEvents()` API (kept, but events screen uses streaming)
