# Menu Bar MCP Running Indicator Design

**Status:** Draft
**Date:** 2026-04-25

## Context

The ClearanceKit GUI hosts the optional MCP server in-process. The server's lifetime is controlled by the `mcpEnabled` feature flag, which `XPCClient` mirrors from opfilter and `AppDelegate` uses to drive `MCPServer.start()` / `MCPServer.stop()`. Today the menu bar icon shows only the connection/version status (`checkmark.shield`, `exclamationmark.shield`, `shield.slash`). Users have no at-a-glance signal that the MCP server is currently accepting connections.

This change adds a small animated red dot, centred on the shield, whenever `mcpEnabled == true`.

## Goal

Provide an at-a-glance menu bar indicator that the MCP server is running, distinct from the existing shield status.

## Non-goals

- No change to the existing healthy/outdated/disconnected shield states.
- No change to `MCPServer` lifecycle, the feature flag, or the XPC contract.
- No new menu items.
- No tests — pure SwiftUI presentation, follows the project convention (CLAUDE.md) of not unit-testing view code.
- No new files — change is confined to `clearancekitApp.swift`.

## Approach

Inline `.overlay` (or equivalent `ZStack`) on the existing `Image(systemName: menuBarIconName)` inside the `MenuBarExtra { ... } label: { ... }` block. The overlay conditionally renders a `Circle` filled `.red` at ~7pt diameter, centred on the shield. The circle's opacity oscillates between 1.0 and 0.4 every ~1s with `.easeInOut`, autoreversing forever, driven by a private `@State` on `clearancekitApp`.

This is approach **A** from brainstorming — chosen over extracting a `MenuBarIconView` because the change is too small to justify a new file, and approach C (separate `Image` + `Circle` in a ZStack with no overlay shorthand) is functionally equivalent but more verbose.

## Behaviour

| `mcpEnabled` | Shield | Dot |
|---|---|---|
| `false` | rendered as today | absent |
| `true` | rendered as today (any of the three states) | 7pt red circle, centred, opacity pulses 1.0 ↔ 0.4 every ~1s |

When `mcpEnabled` flips, the dot appears or disappears with no transition. The shield underneath is unchanged. The dot is rendered above the shield glyph (overlap accepted per the brainstorming Q5 choice — "centred on the shield").

The animation runs continuously for the lifetime of the app process (per brainstorming Q4 option a). When `mcpEnabled == false`, the dot is removed from the view tree, so there is no rendering cost while hidden; the `@State` animation timer continues but has no visible effect.

## Implementation sketch

```swift
@State private var mcpDotOpacity: Double = 1.0

// inside MenuBarExtra label closure:
Image(systemName: menuBarIconName)
    .foregroundStyle(menuBarIconColor)
    .overlay {
        if xpcClient.mcpEnabled {
            Circle()
                .fill(Color.red)
                .frame(width: 7, height: 7)
                .opacity(mcpDotOpacity)
        }
    }
    .onAppear {
        withAnimation(.easeInOut(duration: 1.0).repeatForever(autoreverses: true)) {
            mcpDotOpacity = 0.4
        }
    }
```

Constant for dot size lives inline at the call site; CLAUDE.md prefers named constants but for a single literal in one file the readability cost of extraction outweighs the benefit. If a second usage appears, extract.

## Files touched

- Modified: `clearancekit/App/clearancekitApp.swift` (add `@State`, augment the `MenuBarExtra` label with the conditional dot overlay and the `.onAppear` animation hook).

## Edge cases

- **Mcp enabled flips before `.onAppear` fires:** the animation `@State` defaults to `1.0`. The first paint shows the dot at full opacity, then the animation eases. Acceptable.
- **Dark mode / increased contrast:** `.red` is a fixed colour. Pure red is high-contrast against both light and dark menu bar backgrounds; matches macOS notification badge convention. No further work.
- **Reduced motion accessibility setting:** out of scope — the project does not currently respect `accessibilityReduceMotion`. If it becomes relevant, gate the `withAnimation` block on `@Environment(\.accessibilityReduceMotion)`.

## Testing

No automated tests. Manual verification:

1. Build, install, run.
2. Open Settings → MCP → enable.
3. Confirm a red dot appears centred on the menu bar shield and pulses.
4. Disable MCP. Confirm the dot disappears immediately.
5. Toggle several times in quick succession. Confirm no flicker or stuck-on state.
