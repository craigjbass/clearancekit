---
id: ADR-F07
domain: features
date: 2026-03-07
status: Accepted
---
# ADR-F07: Wildcard Path and Process Matching

## Context

Exact path matching is brittle in practice: versioned app bundles change paths across updates, user home directories vary per machine, framework paths differ across macOS versions, and apps have multiple helper processes with related but distinct paths. Exact process matching fails similarly when apps spawn helpers with slightly different signing IDs. A more expressive matching syntax is needed that remains deterministic and auditable.

## Options

1. Exact match only — simple but breaks on every app update or multi-helper app.
2. Prefix matching — more flexible but cannot match mid-path components or cross directory boundaries selectively.
3. Glob patterns using standard shell glob semantics — familiar, expressive, and compatible with Santa's path matching conventions.

## Decision

Path patterns use glob(3)-compatible syntax. `*` matches any characters within a single path component; `**` as a standalone component matches any number of path levels; `?` matches any single character within a component. Matching is component-boundary-aware so `/opt/clear` never inadvertently matches `/opt/clearancekit`.

FAA rule paths are routed through `santaPath` / `santaPathEntry` for glob(3) conversion before being registered as ES watch items (`cfb81ad`). This converts ClearanceKit's internal glob syntax to the format Santa and the ES kernel expect. FAA paths set `IsPrefix: true` since `protectedPathPrefix` is always a prefix by definition.

For ES kernel muting in the jail adapter, `esMutePath` extracts the longest literal prefix up to the first wildcard component. The kernel delivers a superset of events for wildcard rules; the policy filter narrows them with the full pattern match.

`ProcessSignature` fields support `*` wildcard independently per field: `*:*` matches any process; `*:com.apple.Safari` matches any team's Safari. The `matches` method on `ProcessSignature` was extended with an `|| teamID == "*"` clause.

Rule evaluation order changed from array order to most-specific-path-wins (`d1798c4`): longer, more specific path prefixes are evaluated first. Same-specificity rules fall back to array-order tiebreaking. This prevents broad wildcard rules from shadowing more specific deny rules regardless of the order in which rules were added.

## Consequences

- Most-specific-wins prevents a broad `/**` allow from shadowing a specific deny rule — a correctness improvement over first-match-wins.
- `**` within-component wildcard was added for jail rules where subdirectory trees need to be allowed as a unit.
- Paths exported to Santa are converted via `santaPath` for glob(3) compatibility; Santa export tests pin this conversion.
- Allow-from-event uses the exact event path, never a widened pattern, to avoid unintentional broadening of the resulting rule.
- `classifyPath` promotes the entire path's classification to `ancestryRequired` when any matching rule requires ancestry data, ensuring the hot path never misses an ancestry check.
