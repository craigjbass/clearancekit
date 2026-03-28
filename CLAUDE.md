# ClearanceKit — Developer Guide

## Architecture

ClearanceKit uses hexagonal architecture. Three distinct layers must stay separate:

**Domain** (`Shared/`) — Pure Swift logic with no I/O, framework, or OS dependencies.
- `FAAPolicy.swift` — file-access policy evaluation
- `GlobalAllowlist.swift` — global allowlist matching
- `ProcessTree.swift` — process ancestry service

**Ports** — Swift protocols that define what the domain needs from the outside world.
- `ProcessTreeProtocol` — ancestry lookup
- `ServiceProtocol` / `ClientProtocol` (`XPCProtocol.swift`) — IPC surface

**Adapters** (`opfilter/`, `clearancekit/`) — Concrete implementations that translate between external systems and domain types.

`opfilter/` is organised into subdirectories by adapter role:
- `EndpointSecurity/` — translates Endpoint Security C events → domain types (`ESInboundAdapter`, `ESProcessRecord`, `MutePath`)
- `XPC/` — IPC boundary with the GUI app (`XPCServer`, `ConnectionValidator`, `EventBroadcaster`, `ProcessEnumerator`, `NSXPCConnection+AuditToken`)
- `Database/` — SQLite persistence (`Database`, `DatabaseMigrations`)
- `Policy/` — policy loading, signing, and state management (`PolicyRepository`, `PolicySigner`, `ManagedPolicyLoader`, `ManagedAllowlistLoader`)
- `Filter/` — filter orchestration and output (`FilterInteractor`, `AuditLogger`, `TTYNotifier`)

**Rule**: domain code never imports `EndpointSecurity`, `AppKit`, `SwiftUI`, `SQLite`, or any other infrastructure framework. Adapters own those imports.

## Build and Test

```bash
# Build and test via xcodebuild
xcodebuild test -scheme clearancekit -destination 'platform=macOS'
```

Tests live in `Tests/` and use the Swift Testing framework (`@Suite`, `@Test`, `#expect`).

## Testing Strategy

### New code — TDD
Write the test first. Red → Green → Refactor. Keep the cycle short: one failing assertion at a time.

### Existing untested code — Feathers approach
1. **Characterise before changing.** Write a test that pins the current behaviour exactly, even if that behaviour looks wrong. Do not change any logic yet; only add the test.
2. **Introduce a seam.** Extract an interface or closure parameter so the behaviour under test can be driven without real I/O. Prefer the simplest seam: a `@Sendable` closure injected at the call site beats a full protocol when only one behaviour varies.
3. **Narrow the scope.** Test the smallest unit that isolates the logic you need to change, using a fake collaborator (named `Fake…`, never `Mock…`).
4. **Change under the safety net.** Modify the logic only once a characterisation test is green. Keep commits atomic: characterisation test → logic change → refactoring, each as its own commit.
5. **Do not retrofit tests onto integration boundaries.** Adapter code that calls OS APIs belongs behind a protocol seam so the domain logic can be tested without it.

### What to test
- Domain logic (policy evaluation, path matching, allowlist resolution) must be fully covered.
- Adapters are tested at integration or system level when practical, not unit-level.
- Do not test Swift language mechanics or framework plumbing.

### Test structure
```swift
@Suite("Feature area")
struct FeatureAreaTests {
    @Test("specific observable behaviour")
    func specificObservableBehaviour() async {
        // Arrange
        // Act
        // #expect
    }
}
```

Fake collaborators are private nested structs/classes inside the test file. They implement only the protocol methods exercised by the test.

## Swift Conventions

### Naming
- Names describe intent at the call site, not the implementation.
- No abbreviations. No generic placeholders (`data`, `temp`, `value`, `result`, `info`).
- Prefer nouns for types, verb phrases for methods that perform work.

### Control flow
- Guard clauses first; exit early; reduce nesting.
- No `else` after a `return`, `throw`, or `continue` — extract a method instead.
- Ternaries on one line only; never nested.
- Complex boolean logic lives in a clearly named computed property or method.

### Methods
- Single responsibility. If you need to describe a method with "and", split it.
- Short parameter lists; group related parameters into a dedicated type.
- No side effects in computed properties.

### Collections
- Never return or pass `nil` for a collection; return an empty collection.
- Iterate directly; no `if !collection.isEmpty { for … }` guard before a loop.

### Immutability
- `let` for everything that does not change after initialisation.
- Prefer value types (`struct`, `enum`) for domain models.

### Enums over booleans
- Replace flag parameters and boolean return values with enums that name the cases explicitly.
- Pattern-match on enum cases; never inspect `.rawValue` to drive logic.

### Errors and assertions
- Catch specific error types; never catch the root `Error` and swallow it.
- Do not return invented defaults to paper over failures — surface the error.
- Use `guard`/`precondition`/`fatalError` to enforce invariants that must always hold.
- Only add a guard if the condition is actually reachable.

### Concurrency
- Mark shared mutable state with `OSAllocatedUnfairLock`; avoid `@MainActor` in domain code.
- Ancestry lookups are lazy: pass `@Sendable () async -> [AncestorInfo]` closures and call them only when a rule demands ancestry data.

### Miscellaneous
- Named constants or enums; no magic numbers or strings.
- String interpolation, not concatenation or `String(format:…)`.
- Deserialise structured data into typed models; no raw dictionary key access.
- No fallback defaults unless the requirement explicitly calls for one; extra branches hide intent.
- Update every call site when changing an interface; no backwards-compatibility shims or deprecated aliases.

## Protocol placement

A protocol lives in the same folder as the type(s) that take it as a constructor parameter — the *users* of the abstraction, not the implementors. This keeps the dependency arrow pointing inward: the consumer defines what it needs, and implementors reach in to satisfy it.

The only exception is when the protocol must be visible to both binary targets (clearancekit app and opfilter system extension). In that case `Shared/` is the right home, because it is compiled into both binaries.

**Examples:**
- `PolicyDatabaseProtocol` lives in `opfilter/Policy/` alongside `PolicyRepository`, which takes it in its `init`. ✓
- A protocol consumed only by `opfilter/Filter/` types belongs in `opfilter/Filter/`, even if its concrete implementation lives in `Shared/`. The conformance (`extension ConcreteType: TheProtocol`) is declared in a file within `opfilter/Filter/`, keeping `Shared/` free of the dependency.

## Comments

Code should explain itself through precise naming and small, focused units. Comments are not a substitute for clarity.

**Write a comment only when:**
- The code is correct but the reason it is written that way is non-obvious (e.g. a workaround for a known OS bug with a reference).
- A performance-sensitive section explains *why* a specific algorithm was chosen and what the measured trade-off is.

**Never write:**
- Comments that restate what the code does (`// Increment counter`).
- TODO/FIXME left for future readers without a linked issue.
- Doc-comment boilerplate on every declaration.
- Placeholder prose like "in a real implementation…".
