---
id: ADR-A03
domain: architecture
date: 2026-03-07
status: Accepted
---
# ADR-A03: XPC as IPC Boundary

## Context

The GUI and opfilter are separate processes that need to exchange policy updates (GUI → opfilter) and deny events (opfilter → GUI) in real time. The chosen IPC mechanism must prevent impersonation, support typed message contracts, and be maintainable without third-party serialisation libraries.

Three design concerns shaped the final form: the initial wiring of policy delivery over XPC (commit `31c617c`, 2026-03-07), connection hardening via audit-token validation (commit `7b23e09`, 2026-03-13), and the extraction of `PolicyRepository` and `EventBroadcaster` from the monolithic `XPCServer` (commit `fe044c0`, 2026-03-21).

## Options

1. **Unix domain socket + custom protocol** — full control but requires a custom framing and serialisation layer; no built-in identity verification.
2. **Mach ports directly** — low-level; requires manual message layout and offers no built-in object graph encoding.
3. **NSXPCConnection with a typed protocol** — Apple-provided; handles serialisation of `NSSecureCoding`-conforming types; integrates with the macOS sandbox and code-signing infrastructure; audit token accessible for identity verification.

## Decision

`NSXPCConnection` with `XPCProtocol.swift` (compiled into both `opfilter` and `clearancekit` via `Shared/`) as the sole cross-binary interface. The protocol defines two roles:

- `ServiceProtocol` — methods opfilter exposes to the GUI (policy CRUD, jail rule CRUD, process list, version info).
- `ClientProtocol` — methods the GUI exposes to opfilter for push notifications (deny events, policy updates, jail rule updates, resync).

`XPCServer` in opfilter listens on the Mach service name and validates each connecting client via `ConnectionValidator`. It is started early in the launch sequence — before the process-tree scan — so the GUI can connect and show a loading state immediately. Once all dependencies are ready, `configure(_:)` is called with a `ServerContext` struct that bundles the full object graph (`processTree`, `policyRepository`, `faaInteractor`, `jailInteractor`, `adapter`, `jailAdapter`). This two-phase initialisation keeps the server's listener alive during startup without requiring all collaborators to be constructed before the listener opens.

`ConnectionValidator` uses the **audit token** (not PID) of the connecting process to verify it is Apple-anchored, signed by team `37KMK6XFTT`, carries a bundle ID prefixed `uk.craigbass.clearancekit`, and does not hold dangerous entitlements (`allow-dyld-environment-variables`, `disable-library-validation`, `get-task-allow`). The audit token is read via an Objective-C runtime shim (`NSXPCConnection+AuditToken.swift`) because `auditToken` is not bridged to Swift's Foundation overlay.

`EventBroadcaster` pushes deny events to all registered GUI clients. `ProcessEnumerator` serves process snapshots on demand.

## Consequences

- `XPCProtocol.swift` in `Shared/` is the only file that must be compiled into both binaries; all other XPC code lives exclusively in one target.
- Audit-token validation prevents PID-reuse attacks that would defeat PID-based identity checks.
- `NSXPCConnection` handles `NSSecureCoding` serialisation; no custom framing code is needed.
- Adding a new cross-process operation requires updating the protocol in `Shared/` and implementing both ends — intentionally visible and auditable.
- Dangerous entitlement rejection (skipped in DEBUG builds) ensures even a legitimately signed but weakened binary cannot connect in production.
- The two-phase `start()` / `configure(_:)` split allows the GUI to connect during opfilter startup without blocking on slow initialisation (database load, process-tree scan).
