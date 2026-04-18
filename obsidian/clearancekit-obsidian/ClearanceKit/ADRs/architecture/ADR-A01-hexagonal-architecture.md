---
id: ADR-A01
domain: architecture
date: 2026-03-07
status: Accepted
---
# ADR-A01: Hexagonal Architecture

## Context

opfilter began as a monolith. ES event handling, policy evaluation, XPC communication, audit logging, and TTY notification were all interleaved in a single `main.swift` file (163 lines of mixed concerns before the refactor). There was no separation between what the system *does* (policy logic) and how it talks to the OS (Endpoint Security, SQLite, XPC). This made policy evaluation impossible to test without a live ES client and made adapting individual subsystems risky.

The introduction of a `FilterInteractor` and `ESInboundAdapter` in commit `9074ce8` (2026-03-07) was the first structural cut. The CLAUDE.md rewrite in commit `162979e` (2026-03-20) formalised the three-layer rule across the entire codebase.

## Options

1. **Layered architecture** — horizontal layers (presentation, service, data) with permitted downward calls. Familiar but does not enforce OS-dependency isolation; domain code can still import infrastructure.
2. **Hexagonal / ports-and-adapters** — domain at the centre with no outward dependencies; ports (protocols) define what the domain needs; adapters translate between external systems and domain types.
3. **Keep the monolith** — fastest short-term, but policy logic remains untestable without a running System Extension.

## Decision

Hexagonal architecture with three layers:

- **Domain** (`Shared/`) — pure Swift logic with no I/O, framework, or OS dependencies. Contains `FAAPolicy.swift`, `GlobalAllowlist.swift`, `ProcessTree.swift`, `JailRule.swift`. No imports of `EndpointSecurity`, `AppKit`, `SwiftUI`, or `SQLite`.
- **Ports** — Swift protocols that define what the domain needs from the outside world. `ProcessTreeProtocol`, `ServiceProtocol`, and `ClientProtocol` (in `XPCProtocol.swift`). Each protocol lives beside the type(s) that consume it, not beside the implementor.
- **Adapters** — concrete implementations that translate between external systems and domain types, organised by role under `opfilter/`:
  - `EndpointSecurity/` — `ESInboundAdapter`, `ESJailAdapter`, `ESTamperResistanceAdapter`, `ESProcessRecord`, `MutePath`
  - `XPC/` — `XPCServer`, `ConnectionValidator`, `EventBroadcaster`, `ProcessEnumerator`
  - `Database/` — `Database`, `DatabaseMigrations`
  - `Policy/` — `PolicyRepository`, `PolicySigner`, `ManagedPolicyLoader`, `ManagedAllowlistLoader`
  - `Filter/` — `FAAFilterInteractor`, `JailFilterInteractor`, `FileAuthPipeline`, `AuditLogger`, `TTYNotifier`

Protocol conformances for domain types are declared in adapter files within the consumer's folder, keeping `Shared/` free of adapter-layer dependencies.

## Consequences

- Domain policy logic (`FAAPolicy`, `JailRule`, `GlobalAllowlist`) is fully unit-testable without a running OS or ES client.
- Adapters own all OS-framework imports; the compiler enforces the boundary.
- Adding or swapping an adapter (e.g. replacing SQLite with a different store) requires no changes to domain code.
- Conformance files in adapter directories (`ProcessTree+ProcessTreeProtocol.swift`) keep the dependency arrow pointing inward: consumer → protocol ← implementor.
- The rule is machine-checkable: any `import EndpointSecurity` or `import AppKit` in `Shared/` is a build error waiting to be caught in review.
