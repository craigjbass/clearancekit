---
id: ADR-S05
domain: security
date: 2026-04-12
status: Accepted
---
# ADR-S05: Tamper Resistance Adapter

## Context

A privileged attacker (root, or holding `com.apple.private.security.no-container`) can send SIGSTOP to suspend opfilter, temporarily disabling file-access enforcement without terminating it. The process appears alive but processes no ES events while suspended. This is particularly dangerous because no error is surfaced to the user and enforcement silently stops.

SIGKILL cannot be caught or deferred by user-space code, but other signals and process suspension can be intercepted via the Endpoint Security AUTH event mechanism before they are delivered.

## Options

1. **No protection** — rely on macOS SIP and Transparency to prevent privileged attackers. Does not address the suspension attack surface for root-level actors.
2. **Watchdog process** — a separate process that detects suspension and restarts opfilter. Introduces a second process to secure; race conditions between detection and restart.
3. **ES AUTH subscription to signal and suspend events** — opfilter subscribes to `AUTH_SIGNAL` and `AUTH_PROC_SUSPEND_RESUME` events targeting its own PID and denies them via the AUTH response before delivery. No separate process required.

## Decision

`ESTamperResistanceAdapter` subscribes to `ES_EVENT_TYPE_AUTH_SIGNAL` and `ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME`. For each event, the target PID is checked first:

- **Target is not opfilter's own PID** — the event is allowed and cached immediately. No identity check is performed; these events are not relevant to self-protection.
- **Target is opfilter's own PID** — the source PID is then examined against opfilter's own PID (`ownPID`) and its parent PID (`ownParentPID`):
  - **Source PID matches `ownPID` or `ownParentPID`** — an identity check is performed via `isTrustedBySignature`, reading `signing_id`, `team_id`, and `is_platform_binary` from the `es_process_t` struct. `com.apple.xpc.launchd` (platform binary) is permitted; opfilter itself (matching `XPCConstants.teamID` and `XPCConstants.serviceName`) is permitted. If the identity check fails, the event is denied — this catches processes that have raced to reuse launchd's or opfilter's PID with a different signing identity.
  - **Source PID does not match `ownPID` or `ownParentPID`** — the event is unconditionally denied via `ES_AUTH_RESULT_DENY` with no caching (`false` cache flag). No identity check is performed; any process other than opfilter or its parent that targets opfilter is rejected without further inspection.

DENY events from both branches are forwarded via the `onTamperDenied` closure to `EventBroadcaster`, which pushes a `TamperAttemptEvent` (NSSecureCoding) to connected GUI clients over XPC (wired in `d6a765c`). The GUI displays tamper events in a dedicated sidebar view alongside file-access denials.

Source identity fields (`signing_id`, `team_id`, `is_platform_binary`) are populated by the kernel at event delivery time and cannot be forged by user-space code.

Responses are issued inline in the ES event callback (no async dispatch) to minimise the window between event delivery and denial.

Introduced in `fb88dce`. XPC broadcasting wired in `d6a765c`.

## Consequences

- Process suspension and most signal-based attacks against opfilter are blocked at the kernel level, before delivery.
- SIGKILL cannot be intercepted by any user-space mechanism in macOS. An attacker who can send SIGKILL (root) can still terminate opfilter; this is a documented limitation of the ES framework's AUTH event scope.
- Launchd retains the ability to manage opfilter (start, stop, restart) because it passes the identity check as a platform binary with the expected signing ID.
- Spoofed source processes (correct PID but wrong signing identity) are denied and logged — processes matching opfilter's own PID or parent PID but failing the identity check are blocked by the inner identity check branch.
- Processes with any other PID that target opfilter are denied unconditionally, without an identity check, keeping the fast path short.
- GUI surfaces tamper events in the event list, providing visibility into attack attempts without requiring log inspection.
- opfilter must know its own PID at startup; this is obtained via `getpid()` and `getppid()` at `ESTamperResistanceAdapter` initialisation.
