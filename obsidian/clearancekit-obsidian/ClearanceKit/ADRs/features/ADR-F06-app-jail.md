---
id: ADR-F06
domain: features
date: 2026-03-21
status: Accepted
---
# ADR-F06: App Jail

## Context

FAA rules control which processes can access which paths, but do not confine a process to only its allowed paths. An app could write to arbitrary locations not covered by any deny rule. Containment (jailing) requires a fundamentally different model: deny-by-default for a specific process, with only explicitly permitted paths allowed. macOS sandbox profiles require app changes and are static at launch, making runtime policy adjustments impossible.

## Options

1. No containment — FAA rules only; no deny-by-default per-app confinement.
2. macOS sandbox profiles — require app modifications and approval; static at launch; cannot be changed without process restart.
3. Per-app jail rules via a dedicated ES client subscribing to all AUTH file events unconditionally, with in-process filtering to fast-path non-jailed processes and allowed-path-only semantics for jailed ones.

## Decision

`ESJailAdapter` holds a separate ES client that subscribes unconditionally to all AUTH file events: `AUTH_OPEN`, `AUTH_RENAME`, `AUTH_UNLINK`, `AUTH_LINK`, `AUTH_CREATE`, `AUTH_TRUNCATE`, `AUTH_COPYFILE`, `AUTH_READDIR`, `AUTH_EXCHANGEDATA`, and `AUTH_CLONE`. No ES-level muting is used. Filtering happens in-process: on every file auth event the adapter looks up the process's `(pid, pidVersion)` key in `jailedProcessesLock: OSAllocatedUnfairLock<[ProcessKey: UUID]>`. If the key is absent the process is not jailed, and the event is immediately allowed (with an appropriate cache decision from `JailFileAccessEventCacheDecisionProcessor`) without any policy evaluation. Only processes present in `jailedProcessesLock` proceed to full jail policy evaluation.

This subscribe-all-plus-filter approach was chosen over ES-level muting for two reasons: the jail ES client is fully isolated from the FAA ES client (no shared audit tokens or caches), and the two clients can be toggled independently at runtime without affecting each other's state.

Jail rule data is modelled in `JailRule` (`Shared/`). Allowed paths require explicit wildcard patterns (no implicit subdirectory access — `844141b`). `**` as a standalone path component matches any number of path levels.

Jail enforcement propagates to child processes via FORK/EXEC ancestry tracking (`f55f283`). `ESJailAdapter` tracks `(pid, pidVersion)` pairs to prevent PID reuse from either falsely jailing or falsely releasing a process. `handleJailEventSync` on `FilterInteractor` evaluates the global allowlist and jail policy inline on the ES callback queue — both are synchronous lock reads and predicate checks — then calls `respond()` immediately before dispatching logging and XPC broadcast fire-and-forget via a `Task`. This prevents ENDPOINTSECURITY deadline misses that occurred when async Tasks were spawned per event.

Jail rules are persisted in the SQLite database via `PolicyRepository` and migrated via `DatabaseMigrations`. A background sweep timer fires 10 seconds after startup and repeats every 10 seconds; it scans all live process records to detect processes that were already running when opfilter launched and adds them to `jailedProcessesLock` so they are enforced without waiting for their next EXEC event. The feature is opt-in via an XPC toggle; jail lifecycle (start/stop) is managed independently of FAA.

## Consequences

- Jail is independently toggleable at runtime without affecting FAA enforcement.
- Jail events appear in a dedicated process tree view in the GUI separate from FAA events.
- `(pid, pidVersion)` tracking prevents stale entries from jailing or releasing wrong processes after PID reuse.
- Non-jailed processes are fast-pathed immediately on the callback queue with no policy evaluation, keeping the high event volume cost bounded.
- Synchronous AUTH response on the jail path is safe because the policy lookup is bounded: no database I/O on the hot path.
- Orphaned processes (jailed children whose parent exits first) continue to be enforced until they exit themselves.
- JSON import/export for jail rules is supported.
- Managed jail rules can be delivered via MDM (`JailRules` preference key) and are shown as read-only in `JailView`.
