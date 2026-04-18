---
id: ADR-F02
domain: features
date: 2026-03-15
status: Accepted
---
# ADR-F02: Global Allowlist

## Context

Hundreds of Apple system processes legitimately access all files — Time Machine, Spotlight, XProtect remediators, system frameworks, and more. Building individual FAA rules for each would be impractical, would generate enormous event noise, and would require constant maintenance as Apple ships new system processes. A first-pass bypass mechanism is needed that is evaluated before FAA rules and that can account for processes whose signing identities vary across macOS versions.

## Options

1. Per-process FAA rules for all known system processes — high maintenance burden, pollutes user-visible policy.
2. Team-ID-only bypass for Apple-signed binaries — too broad; allows any Apple-signed binary unconditionally.
3. Separate `GlobalAllowlist` evaluated before FAA rules, matching by `(teamID, signingID)` pairs with wildcard signingID support and platform-binary flag.

## Decision

`GlobalAllowlist` is evaluated as the first step in `evaluateAccess()`, before the in-kernel ES cache check and before FAA rule evaluation. Three tiers are evaluated in order (first match wins):

1. **Baseline** — compiled in; covers essential Apple system processes.
2. **Managed** — delivered via MDM `.mobileconfig` (`GlobalAllowlist` preference key); loaded by `ManagedAllowlistLoader`.
3. **User** — persisted in signed JSON on disk; editable via the GUI Allowlist tab.

`AllowlistEntry` matches on `(teamID, signingID)` pairs; `*` is supported as a wildcard signingID for Apple processes whose identity varies across macOS versions. A `platformBinary` flag matches processes where the ES audit token reports an empty team ID (Apple platform binaries).

`AncestorAllowlistEntry` is a parallel structure for ancestor-based bypasses: if any ancestor in the calling-process chain matches an ancestor allowlist entry, access is granted.

XProtect bundle paths are enumerated at launch. `XProtectWatcher` uses FSEvents on `XProtect.app/Contents/MacOS` to trigger an allowlist reload whenever XProtect remediator binaries change, so the baseline stays current after Apple security updates without requiring opfilter restart.

## Consequences

- Globally-allowed events generate no event log entry; the bypass is silent and does not appear in the GUI events view.
- Globally-allowed events are ES-cached (`cache: true`) so subsequent opens of the same file by the same globally-allowed process incur no callback overhead.
- Auto-resync on XProtect bundle changes eliminates stale allowlist entries after Apple security updates.
- Wildcard signingID support is required because some Apple framework processes vary their signing identity across macOS versions.
- The GUI Allowlist tab shows all three tiers; managed and baseline entries are read-only.
