---
id: ADR-A06
domain: architecture
date: 2026-03-21
status: Accepted
---
# ADR-A06: Dual ES Client Architecture

## Context

ClearanceKit handles two distinct enforcement concerns: **File Access Authorization (FAA)** — authorising or denying `AUTH_OPEN`, `AUTH_RENAME`, and related events for all processes — and **App Jail** — containment of specific processes by restricting their file operations via a separate set of jail rules.

These concerns have different event subscriptions, different latency budgets, and different response strategies. FAA events flow through the two-stage pipeline (see ADR-A07) with post-respond work deferred to a background queue. Jail events must respond synchronously within the ES deadline with no pipeline overhead. Mixing them in a single ES client and a single `FilterInteractor` created both a scheduling conflict and a violation of the Single Responsibility Principle: `FilterInteractor` was simultaneously owning the FAA pipeline path and the synchronous jail path.

Three commits define this decision: the App Jail domain types and initial `FilterInteractor` integration (`9af5bb4`, 2026-03-21), the `AUTH_EXEC` → `NOTIFY_EXEC` switch to remove unnecessary auth latency (`7768ef9`, 2026-03-24), and the split of `FilterInteractor` into `FAAFilterInteractor` and `JailFilterInteractor` (`540674b`, 2026-03-28).

## Options

1. **One ES client handling all event types** — simpler at the OS level (one subscription set); but mixes two response strategies in one handler, and toggling jail at runtime requires re-subscribing the single client.
2. **Separate ES clients per concern** — each client holds its own kernel event queue and subscription set; each can be started, stopped, or reconfigured independently.

## Decision

Two ES clients, two adapters, two interactors:

- `ESInboundAdapter` holds the FAA ES client, subscribed to `AUTH_OPEN`, `AUTH_RENAME`, `NOTIFY_EXEC` (switched from `AUTH_EXEC` to eliminate unnecessary auth latency on exec), and related file-auth events. It feeds `FAAFilterInteractor`.
- `ESJailAdapter` holds the jail ES client, subscribed to `AUTH_OPEN` events for jailed processes. It feeds `JailFilterInteractor`, which responds synchronously within the ES callback.

`FAAFilterInteractor` and `JailFilterInteractor` share a single `AllowlistState` instance (injected at construction) so allowlist updates from `XPCServer` propagate to both interactors atomically.

`XPCServer` takes both interactors as constructor parameters. Jail can be toggled at runtime via XPC without touching the FAA client.

`AUTH_EXEC` was replaced with `NOTIFY_EXEC` on the FAA path (commit `7768ef9`): exec events are needed only for process-tree maintenance, not for authorisation, so requiring a response was unnecessary overhead on every process launch.

## Consequences

- Jail is independently togglable at runtime via XPC; enabling or disabling it does not perturb the FAA event queue.
- Jail responses are deadline-safe: `JailFilterInteractor.handleJailEventSync` responds within the ES callback with no async dispatch.
- FAA events use the two-stage pipeline without interference from jail event handling.
- Two separate ES client subscriptions means two separate kernel event queues; the OS schedules them independently.
- Switching `AUTH_EXEC` to `NOTIFY_EXEC` removed an explicit allow-response from every process launch on the FAA hot path, reducing auth event load.
