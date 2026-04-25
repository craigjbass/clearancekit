# Menu Bar MCP Running Indicator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show a small animated red dot centred on the menu bar shield while `XPCClient.shared.mcpEnabled == true`.

**Architecture:** Inline `.overlay` on the existing `Image(systemName: menuBarIconName)` in `MenuBarExtra { ... } label: { ... }` inside `clearancekit/App/clearancekitApp.swift`. Animation is a private `@State var mcpDotOpacity: Double = 1.0` driven by `withAnimation(.easeInOut(duration: 1.0).repeatForever(autoreverses: true))` started in `.onAppear`. Conditional render via `if xpcClient.mcpEnabled`. No new files, no tests.

**Tech Stack:** Swift, SwiftUI (`MenuBarExtra`, `Image(systemName:)`, `Circle`, `withAnimation`, `@State`).

**Reference:** Spec at `docs/superpowers/specs/2026-04-25-menu-bar-mcp-indicator-design.md`.

---

## File structure

| File | Role |
|---|---|
| `clearancekit/App/clearancekitApp.swift` (modify) | Add `@State` opacity, modify the `MenuBarExtra` label to overlay a conditional pulsing red `Circle`, start the animation in `.onAppear`. |

No new files. No new tests. Manual verification only.

---

## Task 1: Add the pulsing MCP indicator overlay

**Files:**
- Modify: `clearancekit/App/clearancekitApp.swift`

- [ ] **Step 1: Read the current `MenuBarExtra` label to confirm shape**

Run: `grep -n "MenuBarExtra\|Image(systemName: menuBarIconName)\|.foregroundStyle(menuBarIconColor)" clearancekit/App/clearancekitApp.swift`

Expected output includes lines around the existing label:

```
MenuBarExtra {
    ...
} label: {
    Image(systemName: menuBarIconName)
        .foregroundStyle(menuBarIconColor)
}
```

If the existing block differs materially from this, stop and report — the rest of the plan assumes that exact shape.

- [ ] **Step 2: Add a private `@State` to `clearancekitApp`**

In `clearancekit/App/clearancekitApp.swift`, find the `clearancekitApp` struct's existing `@State` / `@Environment` / `@StateObject` declarations (near the top of the struct, immediately after `@NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate`).

The current declarations look like:

```swift
@main
struct clearancekitApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @Environment(\.openWindow) private var openWindow
    @ObservedObject private var nav = NavigationState.shared
    @StateObject private var xpcClient = XPCClient.shared
```

Insert a new `@State` line directly after `@StateObject private var xpcClient = XPCClient.shared`:

```swift
    @State private var mcpDotOpacity: Double = 1.0
```

- [ ] **Step 3: Replace the `MenuBarExtra` label closure**

In the same file, find the existing label closure:

```swift
        } label: {
            Image(systemName: menuBarIconName)
                .foregroundStyle(menuBarIconColor)
        }
```

Replace it with:

```swift
        } label: {
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
        }
```

- [ ] **Step 4: Build**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS' 2>&1 | tail -3`
Expected: `** BUILD SUCCEEDED **`.

- [ ] **Step 5: Run the test suite to confirm no regression**

Run: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | tail -3`
Expected: `** TEST SUCCEEDED **`.

- [ ] **Step 6: Commit**

```bash
git add clearancekit/App/clearancekitApp.swift
git commit -m "feat: pulse a red MCP indicator dot on the menu bar shield"
```

---

## Task 2: Manual verification

**Files:** none.

- [ ] **Step 1: Build and install the dev app + system extension**

Run: `xcodebuild build -scheme clearancekit -destination 'platform=macOS'`
Install per the project's normal dev workflow.

- [ ] **Step 2: Confirm the dot is absent when MCP is off**

With MCP disabled (default), the menu bar shield should appear unchanged from current behaviour. No red dot.

- [ ] **Step 3: Enable MCP and confirm the pulsing dot**

Open the app window. Navigate to the MCP settings (or wherever MCP is toggled). Enable MCP. Within ~1 second the menu bar shield should show a red dot centred over the shield, pulsing opacity between 1.0 and 0.4 every ~1 second.

- [ ] **Step 4: Disable MCP and confirm the dot disappears**

Disable MCP. The dot should disappear immediately. The shield underneath remains unchanged.

- [ ] **Step 5: Toggle several times in quick succession**

Enable / disable MCP rapidly. Confirm no flicker, no stuck-on dot, no orphaned animation state.

- [ ] **Step 6: Commit only if a fix was needed**

If verification revealed a bug, file a follow-up task in this plan rather than amending. If verification passed, no commit.

---

## Self-review

**Spec coverage**

- Goal *animated red dot when MCP running* — Task 1 step 3.
- Goal *centred on shield* — `.overlay` default alignment is `.center`; the `Circle().frame(width: 7, height: 7)` lands centred on the `Image`.
- Non-goal *no change to existing shield states* — `Image(systemName: menuBarIconName).foregroundStyle(menuBarIconColor)` line preserved verbatim.
- Non-goal *no `MCPServer` lifecycle change* — no edits outside the label closure and one `@State`.
- Non-goal *no new files / no tests* — Task 1 modifies only `clearancekit/App/clearancekitApp.swift`; Task 2 is manual only.
- Behaviour table *dot absent when `mcpEnabled == false`* — `if xpcClient.mcpEnabled` gate.
- Behaviour table *7pt diameter, pure red* — `Circle().fill(Color.red).frame(width: 7, height: 7)`.
- Behaviour table *opacity 1.0 ↔ 0.4 every ~1s easeInOut autoreverse forever* — `withAnimation(.easeInOut(duration: 1.0).repeatForever(autoreverses: true)) { mcpDotOpacity = 0.4 }`.
- Edge case *animation `@State` defaults to 1.0 before `.onAppear`* — `@State private var mcpDotOpacity: Double = 1.0`.
- Edge case *dark mode* — `Color.red` is high-contrast on both backgrounds; spec accepts no further work.
- Edge case *reduced motion* — out of scope per spec; no task.

**Placeholder scan** — none.

**Type consistency** — `mcpDotOpacity: Double` declared once and referenced once. `xpcClient.mcpEnabled` is the existing `@Published private(set) var mcpEnabled = false` on `XPCClient` (verified in `clearancekit/App/XPCClient.swift:40`). `menuBarIconName: String` and `menuBarIconColor: Color` are existing computed properties on `clearancekitApp` (verified in `clearancekit/App/clearancekitApp.swift:154` and `:162`); they are not modified.
