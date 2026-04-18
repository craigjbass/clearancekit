---
id: ADR-A05
domain: architecture
date: 2026-03-07
status: Accepted
---
# ADR-A05: ProcessSignature as Process Identity

## Context

Process identity in ES events is expressed as two separate fields: a `team_id` and a `signing_id`. Early policy rules stored these as independent arrays (`allowedTeamIDs: [String]`, `allowedSigningIDs: [String]`) and evaluated them with OR semantics — a process matched if *either* its team ID appeared in `allowedTeamIDs` *or* its signing ID appeared in `allowedSigningIDs`. This created ambiguity: a rule intended to allow `com.apple.Safari` could inadvertently allow any process sharing Safari's signing ID regardless of its team.

A second complication: Apple platform binaries carry an **empty** `team_id` in their code signature. Representing them consistently required special-casing throughout policy evaluation, the GUI, and the database.

Four commits shaped this decision: AND-semantics enforcement (`1bf97be`, 2026-03-03), the `apple` sentinel introduction (`91a438c`, 2026-03-07), the `ProcessSignature` composite type (`4d8bb89`, 2026-03-15), and the consistent normalisation of empty team IDs at all four ingestion points (`b04d0a3`, 2026-03-26).

## Options

1. **Keep separate team ID / signing ID fields** — OR semantics, continued empty-string special-casing scattered across evaluation code.
2. **Require both fields always** — AND semantics enforced at the data model level, but still two separate fields; empty-string special-casing still needed.
3. **Pair them as a `ProcessSignature` composite type** — AND semantics, single encoding, one place to handle the `apple` sentinel, wildcard supported per field independently.

## Decision

`ProcessSignature` is a struct pairing `(teamID: String, signingID: String)`, encoded as `"teamID:signingID"` (e.g. `"apple:com.apple.Safari"`, `"37KMK6XFTT:*"`). Policy evaluation treats the pair as AND: both fields must match for a rule to grant access.

The `apple` sentinel replaces the empty-string team ID for all validly signed Apple platform processes. Normalisation is applied at every point where a team ID is derived from a code signature:

- `codeSigningInfo()` in `ProcessTree.swift` (initial process-tree build path)
- `codeSigningIDs()` in `ProcessEnumerator.swift` (XPC `fetchProcessList` path)
- `processRecord(from:)` in `ESProcessRecord.swift` (ES fork/exec path)
- `fileAuthEvent` construction in `ESInboundAdapter.swift` (auth event path)

Rule: if `rawTeamID` is empty and `signingID` is non-empty, use `"apple"`. Unsigned processes (both fields empty) remain unchanged.

Wildcard `*` is supported independently per field: `"37KMK6XFTT:*"` matches any process signed by that team; `"*:*"` matches any process.

`ProcessSignature` is used in `FAARule.allowedSignatures`, the global allowlist, and ancestor allowlist entries.

Database migration 002 converted existing rows from the cross-product of old `team/signing ID` arrays into the new combined format.

## Consequences

- AND semantics eliminate the class of bugs where a broad signing-ID match grants unintended access.
- The `apple` sentinel is consistently used in logs, the GUI, rules, and the database — no empty-string comparisons anywhere in policy code.
- Wildcard semantics are explicit in the type rather than implicit in evaluation logic.
- The encoded `"teamID:signingID"` string is human-readable in the database and in log output.
- The migration from two-array to paired format was a one-time data transformation; no backwards-compatibility shim remains.
