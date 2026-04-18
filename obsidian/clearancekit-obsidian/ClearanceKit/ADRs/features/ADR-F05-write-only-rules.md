---
id: ADR-F05
domain: features
date: 2026-04-10
status: Accepted
---
# ADR-F05: Write-Only Rules (AccessKind)

## Context

Some legitimate processes need read access to protected paths — Time Machine reading a protected directory for backup, indexing services reading files for search, and backup agents scanning home directories. The security concern in these scenarios is write access, not read access. Denying reads would break backups, search, and other legitimate read-heavy workloads. A mechanism is needed to restrict a rule to only the write direction without creating separate read-rule and write-rule types.

## Options

1. Deny all access — too restrictive; breaks Time Machine, Spotlight, and similar.
2. Separate read-rule and write-rule types — doubles the rule model complexity and GUI surface.
3. `enforceOnWriteOnly` flag on the existing `FAARule` — additive; read events fall through to subsequent rules.

## Decision

`AccessKind` enum (`.read` / `.write`) is derived at the adapter boundary from ES open flags: any of `FWRITE`, `O_APPEND`, or `O_TRUNC` classifies the open as a write. `AUTH_RENAME`, `UNLINK`, `LINK`, `CREATE`, `TRUNCATE`, `COPYFILE`, `EXCHANGEDATA`, and `CLONE` are intrinsically writes. `AUTH_READDIR` is `.read`. The classifier lives in `opfilter/EndpointSecurity/AccessKindClassifier.swift` so the domain layer never needs to know Darwin fcntl constants.

`FAARule` gains a `Bool enforceOnWriteOnly` field defaulting to `false`, decoded as an optional for backward compatibility — old serialised policies omit the key and the field defaults to `false`.

The evaluator skips write-only rules on `.read` `AccessKind` events and falls through to subsequent rules. This is additive: a read that hits a write-only rule sees later rules covering the same path. First-match-wins still applies within a given access kind.

Write-only rule matches must not be ES-cached. The `bd916e9` commit documents that caching a read-allow for a write-only rule match would poison subsequent write checks for the same `(process, path)` pair via the kernel cache. A regression test pins this property: a write-only rule covering a read event must respond with `cache: false`.

`AccessKind` is threaded from ES event open flags into `FileAuthEvent` and through `FileAuthPipeline` and policy evaluation. `enforceOnWriteOnly` is exported in all three policy formats: ClearanceKit mobileconfig, MDM plist (`EnforceOnWriteOnly` key), and Santa export (`AllowReadAccess`).

## Consequences

- Cache invalidation logic explicitly excludes write-only rule matches from being cached — this is a correctness constraint, not a performance choice.
- Write-only rules enable layered policy: add a write-only rule for a sensitive path to restrict writes while leaving reads available to backup and indexing tools.
- `AccessKindClassifier` is unit-tested independently of the pipeline.
- The MCP server exposes `enforce_on_write_only` in `add_rule` and `update_rule` tools; `update_rule` preserves the existing value when the parameter is omitted.
- `list_rules` and `list_presets` via MCP render a `[writes only]` tag next to rules where the flag is set.
