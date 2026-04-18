---
id: ADR-F09
domain: features
date: 2026-03-15
status: Accepted
---
# ADR-F09: Preset Drift Detection

## Context

macOS app updates introduce new helper processes with new signing identities. An installed preset from an older version of ClearanceKit would be missing these new process identities, causing unexpected denies after the app update with no visible indication to the user of why. Silent automatic updates would change policy without user awareness or consent, which is unacceptable for a security tool.

## Options

1. No detection — user must manually compare installed rules against the current built-in preset definition. Silent failures occur after app updates.
2. Automatic silent update — update presets without user knowledge. Changes security policy invisibly.
3. Per-row drift badge with explicit user-initiated update action requiring Touch ID.

## Decision

`FAARule` is made `Equatable` so installed preset rule process lists can be compared against the current built-in definition at display time. On each render of `PresetsView`, each installed preset's applied rules are compared to the current `builtInPresets` definition.

When the built-in definition has new content that the installed version lacks, a blue "update available" badge is shown on the preset row. A per-row Update button and a bulk "Update All" toolbar button are offered.

The update action replaces the installed rule's process list with the current built-in version. It goes through the same Touch ID-gated mutation flow as user rule changes — `PolicyStore.addAll` / `removeAll` — so the user explicitly authorises the policy change.

Drift is keyed by UUID: stable preset rule UUIDs are the identity by which installed rules are matched to their built-in counterpart. A UUID that changes post-ship would cause drift detection to lose track of the installed rule.

## Consequences

- Preset rule UUIDs must be permanently stable post-ship. This is an invariant shared with ADR-F04.
- Users retain full control over when preset updates apply. A preset that has drifted continues to enforce the old process list until the user explicitly updates.
- "Update" replaces only the process list of the installed rule. Path and other rule fields are not changed by a preset update.
- Bulk "Update All" processes all drifted presets in a single Touch ID prompt.
- The drift comparison is performed at display time; no background polling or notification is required.
