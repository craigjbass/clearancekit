---
id: ADR-A09
domain: architecture
date: 2026-05-23
status: Accepted
extends: ADR-A06, ADR-S05
---
# ADR-A09: Accept Three-Client Cost Against 48-Client System Limit

## Context

macOS enforces a hardcoded, system-wide limit of **48 concurrent Endpoint Security clients**. The limit is per-machine, not per-application: every ES client across every installed security tool, Apple's own internal subscribers, and any debugging tools all draw from the same pool. Once exhausted, `es_new_client` returns `ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS` and no new clients can be created until existing ones are released.

ClearanceKit's `opfilter` system extension currently opens **three** ES clients, instantiated in `opfilter/main.swift`:

| Adapter | ADR | Purpose |
|---------|-----|---------|
| `ESInboundAdapter` | [[ADR-A06-dual-es-client]] | FAA path-based policy enforcement |
| `ESJailAdapter` | [[ADR-A06-dual-es-client]] | Process jail enforcement |
| `ESTamperResistanceAdapter` | [[ADR-S05-tamper-resistance-adapter]] | Block signal/suspend attacks on opfilter |

Each of those ADRs justified the *existence* of its client in isolation. None weighed the cumulative slot-cost against the 48-client system ceiling, because that constraint was not part of the design budget at the time. This ADR records the decision to accept the three-slot cost rather than collapse clients to reclaim slots.

### Cumulative budget on a real machine

Other security and EDR tools each consume one or more ES client slots from the same 48-slot pool; per-tool counts vary by product, version, and configuration, and have not been verified here. Apple's own `endpointsecurityd` retains an opaque handful of internal subscribers. A typical end-user Mac with one or two security tools sits well below the ceiling; a heavily-stacked enterprise endpoint with multiple EDR products plus ClearanceKit can plausibly approach the low double digits but remains far short of 48 in any documented configuration.

The relevant fact for this decision is that three is a meaningful share of a per-tool budget — large enough that adding a fourth client should not be done casually, small enough that the 48-slot ceiling is not at risk under any realistic deployment.

## Options

1. **Refactor to a single multiplexed ES client.** Combine all subscription sets (FAA + Jail + tamper) into one client. Demultiplex events in the handler by event type and audit-token lookup. Reclaims two slots. Costs: re-entangles the three response paths that ADR-A06 and ADR-S05 deliberately separated; reintroduces the scheduling conflict between the two-stage pipeline (ADR-A07), the synchronous jail path, and the inline tamper response; makes runtime toggling of jail (currently a client start/stop) much more invasive; tamper-resistance becomes harder to reason about as a security boundary when it shares a client with general FAA logic.
2. **Partial collapse — fold tamper-resistance into the FAA client.** FAA already handles AUTH events inline; tamper events could ride the same client. Reclaims one slot. Costs: tamper-resistance loses its security isolation (a bug in FAA event handling could now affect self-protection), and the tamper client's narrow subscription set (`AUTH_SIGNAL`, `AUTH_PROC_SUSPEND_RESUME`) ceases to be a separate, auditable surface.
3. **Dynamic client lifecycle.** Open the jail client only while at least one jail rule is active, close it otherwise. Reclaims a slot opportunistically. Costs: adds a new lifecycle state machine, races between rule mutation and client creation, and incident-class bugs where the client fails to open under load.
4. **Keep three clients.** Pay the three-slot cost. Preserves the architectural separation rationales of ADR-A06 and ADR-S05. Costs: three slots consumed on every ClearanceKit install; ClearanceKit will not coexist cleanly with another tool that *also* takes liberties with the slot budget if a future stack pushes the total near 48.

## Decision

**Option 4: keep three clients.** The 48-slot ceiling is not a realistic constraint for any documented user environment, and the architectural guarantees of the constituent ADRs — independent client toggling, deadline-safe synchronous jail responses, no pipeline interference, and an isolated tamper-resistance security boundary — are load-bearing. Spending architectural simplification or weakening a security boundary to save one or two slots in a 48-slot pool is a bad trade today.

Option 1 (full multiplexing) is reconsidered if a future feature requires a fourth ES client. At four, the cumulative complexity of one multiplexed handler becomes worth its cost.

Option 2 (folding tamper into FAA) is explicitly rejected on security-isolation grounds — the separation in ADR-S05 is the value, and merging negates it.

Option 3 is rejected as adding failure modes (open-on-demand under load) that are worse than the resource cost it avoids.

## Consequences

- ClearanceKit continues to consume three ES client slots per install. Documented as a known cost in this ADR.
- A troubleshooting note belongs in the README covering `ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS`: direct users to enumerate competing tools via `systemextensionsctl list`, confirm the 48-slot ceiling has been reached system-wide rather than within ClearanceKit alone, and note that a fresh-installed Mac with only ClearanceKit will draw three of the 48.
- Any future ES-client addition re-opens this ADR. A fourth client triggers re-evaluation of Option 1 (full multiplexing); new features should subscribe to an existing client where possible.
- The architectural rationales in [[ADR-A06-dual-es-client]] and [[ADR-S05-tamper-resistance-adapter]] remain in force. This ADR adds the cumulative resource-cost analysis that neither weighed.
