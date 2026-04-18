---
id: ADR-F01
domain: features
date: 2026-03-03
status: Accepted
---
# ADR-F01: Process Ancestry Tracking

## Context

Knowing which process opened a file is insufficient for security policy. A shell script launched by a trusted build tool is meaningfully different from the same shell script launched by malware. Ancestry-aware rules can allow `bash` when it is a descendant of a trusted build tool but deny it otherwise. The initial implementation resolved ancestry on each AUTH_OPEN event by walking `proc_pidinfo` PIDs and calling the Security framework per-event, which introduced per-event latency and PID reuse races.

## Options

1. No ancestry — evaluate only the immediate process signing identity.
2. Single-parent check — look one level up using the ES-provided `parent_audit_token`.
3. Full ancestry chain maintained in memory via FORK/EXEC/EXIT ES NOTIFY events plus an initial scan of running processes.

## Decision

`ProcessTree` in `Shared/` maintains full process ancestry in memory. It subscribes to `ES_EVENT_TYPE_NOTIFY_FORK`, `NOTIFY_EXEC`, and `NOTIFY_EXIT` events to keep the tree current. An initial scan of running processes using `proc_listallpids` seeds the tree at startup.

`ProcessIdentity(pid, pidVersion)` is the tree key, where `pidVersion` comes from the audit token's monotonically incrementing slot. This makes the identity globally unique and survives PID reuse. A `pid → ProcessIdentity` reverse index lets initial-scan entries (pidversion 0) resolve until replaced by live ES events carrying the real pidVersion.

`ProcessTreeProtocol` enables lazy lookup: ancestry closures are passed as `@Sendable () async -> [AncestorInfo]` and called only when a rule actually demands ancestor data. `ProcessTree` lives in `Shared/` so it compiles into both the opfilter system extension and the clearancekit GUI binary.

## Consequences

- Ancestry lookups are O(1) after the initial tree build; the per-event Security framework walk is eliminated.
- CPU cost of subscribing to FORK/EXEC/EXIT events is documented as a user-visible warning.
- A race condition for AUTH_OPEN events arriving before NOTIFY_EXEC was fixed (debug logging and fail-safe denial path added in `8da6da8`).
- Ancestry data is retained for 60 seconds after process exit to cover late-arriving AUTH events from short-lived processes.
- `AncestorInfo` carries `(path, teamID, signingID)` so rules can match ancestors by signing identity, not just path.
