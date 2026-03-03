# Coding Standards

## Naming
- Use descriptive names that clearly convey intent
- No abbreviations or generic names like `data`, `temp`, or `value`

## Control Flow
- Use guard clauses to exit early and reduce nesting
- No `else` blocks — return early or extract methods
- Keep ternary expressions simple; never nest them or span multiple lines
- Extract complex boolean expressions into clearly named methods

## Methods
- Short, single-responsibility methods
- Keep parameter lists short; group related parameters into types
- No side effects in property getters

## Collections
- Never return or pass `nil`/`null` for collections; use empty collections
- No `if (!empty) { for ... }` — just iterate directly
- Use collection/object initializers

## Immutability
- Prefer immutable data; use `let` over `var` where possible
- `let` for anything set only at init time

## Errors and Assertions
- Don't catch broad/generic error types; catch specific ones
- Don't swallow exceptions and return invented default values — this hides bugs and moves the failure away from its source
- Use runtime assertions (`guard`, `precondition`, `fatalError`) to enforce invariants instead of defensive fallbacks
- Only guard against things that are actually possible

## Miscellaneous
- No magic numbers or strings — use named constants or enums
- No flag booleans for controlling logic; prefer enums or state types
- Use string interpolation, not concatenation or format calls
- Deserialize structured data into typed models — no manual JSON manipulation
- No fallback/default behaviours unless explicitly asked for; every extra branch adds complexity
- When refactoring, update all call sites — no backwards-compatibility shims or deprecated aliases
- Never write placeholder comments like "in a real implementation..." or stub methods that pretend to do something. If something is unclear, ask.
