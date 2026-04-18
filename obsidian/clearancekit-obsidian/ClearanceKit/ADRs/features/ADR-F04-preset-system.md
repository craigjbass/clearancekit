---
id: ADR-F04
domain: features
date: 2026-03-15
status: Accepted
---
# ADR-F04: Preset System

## Context

Users need a starting point for common apps (Safari, Mail, Chrome, Slack, Discord, Signal, HEY, Notes, and others) rather than building rules from scratch via discovery mode. Manually researching each app's process signing identities is tedious and error-prone. The preset mechanism must also accommodate drift: macOS app updates introduce new helper processes with new signing identities, so an installed preset from an older ClearanceKit version can silently miss new processes.

## Options

1. No presets — users build all rules manually.
2. Hardcoded static rule list embedded in a single file — hard to maintain, no per-app isolation.
3. `AppPreset` structs with stable UUIDs per rule, split into individual files per app, with drift detection built on top.

## Decision

`AppPreset` structs are bundled with the app. Each app's preset lives in its own file under `clearancekit/Configure/AppProtections/Presets/` (e.g. `Safari.swift`, `Chrome.swift`, `HEY.swift`). The `builtInPresets` function in `index.swift` assembles all presets.

Each `FAARule` inside a preset carries a UUID generated via `uuidgen` — never hand-crafted. These UUIDs are stable across releases because the database signing system uses them as keys. New process identities for an existing app can be added to that preset's rule list without changing existing UUIDs.

Enabling a preset requires a single Touch ID prompt regardless of the number of rules it contains, using batch `addAll` / `removeAll` on `PolicyStore`. Enabled rules appear in the Policy tab as regular user rules. Presets are rendered as non-editable rows in the App Protections tab; the enable/disable toggle is the only affordance.

Policy export (`b39d99a`) syncs preset content: preset rules are included in the exported policy document with their stable UUIDs so they survive a policy round-trip.

## Consequences

- Preset rule UUIDs must never change after the rule ships — the database signing system uses UUID as a key.
- New process identities for an existing app are added to the existing preset file; a new UUID is generated for each new `FAARule` entry.
- The preset file structure makes code review of preset additions straightforward: each app is a single self-contained file.
- Drift detection (ADR-F09) builds directly on top of this foundation by comparing installed rule process lists against the current built-in definition keyed by UUID.
- Presets cannot be edited by the user; customisation is done by adding user rules in the Policy tab.
