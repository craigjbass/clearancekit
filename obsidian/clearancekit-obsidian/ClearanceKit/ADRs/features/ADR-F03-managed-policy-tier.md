---
id: ADR-F03
domain: features
date: 2026-03-13
status: Accepted
---
# ADR-F03: Managed Policy Tier

## Context

Enterprises need to deploy policy via MDM that users cannot override. The built-in baseline covers Apple system processes. Enterprises need a separate tier for their own corporate policy — one that sits between the baseline and user rules, is locked down by the MDM admin, and is surfaced as read-only in the GUI so users understand why they cannot modify it. A single monolithic policy that merges MDM and user rules would make it impossible to distinguish managed from user-created rules.

## Options

1. Embed MDM rules in the baseline — users cannot distinguish them from Apple system rules; admin loses visibility.
2. MDM rules replace user rules entirely — eliminates user customisation and creates friction for BYOD scenarios.
3. Separate managed tier evaluated between baseline and user rules, rendered as read-only in the GUI with a lock badge.

## Decision

Three-tier evaluation order: **baseline allowlist → managed policy (MDM) → user rules**. Each tier is evaluated in sequence; the first match wins.

`ManagedPolicyLoader` reads the `FAAPolicy` preference key via `CFPreferencesCopyAppValue`, which merges the macOS managed preferences layer (MDM-delivered `.mobileconfig` profiles). It runs as root inside opfilter so the managed preferences location (`/Library/Managed Preferences`) cannot be shadowed by unprivileged users.

`ManagedAllowlistLoader` reads the `FAAAllowlist` key via the same mechanism for the managed allowlist tier.

`ManagedJailRuleLoader` / `ManagedJailRuleParser` read the `JailRules` preference key for managed jail containment rules.

The GUI shows managed rules with a lock badge and suppresses edit, delete, and allow-event affordances for those rows. Managed rules cannot be exported (they are system-supplied and re-delivered by MDM). A `loadWithSync()` variant flushes the CFPreferences cache before reading so freshly delivered MDM payloads are picked up on resync without restarting opfilter.

The repo includes a reference `.mobileconfig` (`scripts/clearancekit-managed-policy.mobileconfig`) demonstrating the plist schema with `PayloadScope=System`.

## Consequences

- MDM admin can lock down policy without overwriting user customisations.
- Users cannot delete managed rules via the Touch ID flow.
- `ManagedPolicyLoader` and `ManagedAllowlistLoader` are tested with unit tests covering all parsing edge cases including missing fields, invalid signatures, and empty arrays.
- Managed rules are pushed to GUI clients alongside user rules on every resync; the XPC payload carries both tiers separately so the GUI can render them distinctly.
- Jail rules from MDM are shown as a read-only "Managed Jail Rules" section in `JailView`.
