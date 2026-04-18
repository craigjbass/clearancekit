---
id: ADR-A08
domain: architecture
date: 2026-03-28
status: Accepted
---
# ADR-A08: Protocol Placement Convention

## Context

Protocols were initially placed in the same file or folder as their concrete implementations. This reversed the dependency arrow: `Shared/ProcessTree.swift` defined `ProcessTreeProtocol` alongside `ProcessTree`, meaning the `Shared/` layer "knew about" what `opfilter/Filter/` types needed. This is the wrong direction in hexagonal architecture — the consumer should define what it needs, and the implementor reaches in to satisfy it.

Two commits formalised the rule: the CLAUDE.md addition of the protocol placement rule (`ff065b5`, 2026-03-28) and the concrete relocation of `ProcessTreeProtocol` and `PolicyServiceProtocol` to their consumer directories (`2f7ba60`, 2026-03-28).

## Options

1. **Protocols near implementations** — co-location is easy to find, but the implementor drives the interface shape rather than the consumer; upward dependencies accumulate in Shared/.
2. **Protocols always in Shared/** — avoids import issues between targets, but forces Shared/ to know about every consumer's needs; Shared/ becomes a dumping ground.
3. **Protocols near consumers** — the consumer defines what it needs; implementors reach into the consumer's folder to declare conformance; dependency arrow always points inward.

## Decision

A protocol lives in the same folder as the type(s) that take it as a constructor parameter — the *consumers* of the abstraction, not the implementors.

**Exception:** when a protocol must be visible to both binary targets (`clearancekit` and `opfilter`), it lives in `Shared/` because that is the only folder compiled into both binaries. `ServiceProtocol` and `ClientProtocol` in `XPCProtocol.swift` are examples.

**Conformance** is declared in a file within the consumer's folder, not in the implementor's folder. This keeps `Shared/` free of adapter-layer dependencies.

**Concrete examples after the relocation:**

- `ProcessTreeProtocol` extracted from `Shared/ProcessTree.swift` → `opfilter/Filter/ProcessTreeProtocol.swift` (consumers: `FAAFilterInteractor`, `FileAuthPipeline`, `XPCServer`, `ESJailAdapter` are all in `opfilter/`). Conformance declared in `opfilter/Filter/ProcessTree+ProcessTreeProtocol.swift`.
- `PolicyServiceProtocol` moved from `clearancekit/App/` → `clearancekit/Configure/` (consumers: `PolicyStore`, `AllowlistStore`, `JailStore` are all in `clearancekit/Configure/`). It lives at the `Configure/` level rather than a sub-folder because its consumers span multiple sub-directories (`Configure/Policy/`, `Configure/Jail/`, etc.); placing it at the parent level keeps it equally close to all of them without creating an artificial sub-folder that would serve only as a protocol home.
- `PolicyDatabaseProtocol` lives in `opfilter/Policy/` alongside `PolicyRepository`, which takes it in its `init`.

## Consequences

- The dependency arrow consistently points inward: consumer → protocol ← implementor. No upward dependencies from domain/shared code onto adapter-layer shapes.
- `Shared/` contains only types needed by both binaries; it does not grow with every new consumer abstraction.
- Finding the protocol for a given consumer type is deterministic: look in the same folder as the consumer.
- Adding a new adapter implementation requires only: implementing the protocol and declaring the conformance extension in a file inside the consumer's folder. No changes to `Shared/` or to the consumer.
- The rule is documented in CLAUDE.md and enforced by code review; there is no compiler enforcement, so discipline at the call site matters.
