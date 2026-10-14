---
name: e2e-coverage-validation
description: Use when the user wants to PROVE a feature is fully covered by end-to-end tests — find the untested scenarios, validate e2e coverage, audit coverage before a PR or deploy, or answer "what scenarios / fault conditions / validation errors are missing an e2e test". Triggers — "is this feature fully covered by e2e", "validate the e2e coverage for X", "find the test gaps", "what scenarios aren't tested", "which paths have no e2e", "coverage audit", "mutation-style path audit", "did we cover every error / validation / fault condition", "cover all the branches", "e2e gap analysis", "/e2e-coverage", "/coverage-audit". Covers BOTH the server-side paths (branches, error values, permission levels, data access) AND the front-end paths (routes, guards, template branches, form validation, hidden dialogs), joined against the real tests. NOT for RUNNING the suites, NOT for reviewing a diff, NOT for writing the missing tests.
---

# E2E Coverage Validation — prove every path has a test, list the gaps

**Job:** given a feature, enumerate **every** route through its code (mutation-test style — each branch is a "mutant" a test must kill), enumerate **every** existing test, join the two, and produce a ranked list of the scenarios that have **no** end-to-end test or only a **weak** one. Covers success paths, all validation conditions, and all fault conditions, on both the server and the front end. This is a **read-only audit** — it does not write or run tests. It hands writing off only on the user's go.

**Honest-state rule (non-negotiable):** never report "✅ covered" while any fault-condition or validation path is bare. An unexercised error value, a permission level with no negative test, or a happy-path-only test IS a gap — report it at the TOP, ranked by severity. A green summary over hidden gaps is a failure of this skill.

## Setting it up in your repo

Filled in for clearancekit:

1. **The oracle** — `CLAUDE.md` (architecture, testing strategy, Swift conventions), `SECURITY.md`, the threat model in `threatmodel/` (not committed, so it may be absent), and the TLA+ model of the ES AUTH deadline in `tla/ESAuthDeadline.tla`.
2. **Where the tests live** — see the next section.
3. **The feature decomposition** — see "What a feature decomposes into".
4. **The assertion oracle** — there is no automated UI or system test harness. The strongest automated assertion is a Swift Testing `#expect` on the decision or the response sent to a fake `EndpointSecurityAPI` (for example `respondAuthResult` with `ES_AUTH_RESULT_DENY` and the `cacheable` flag), or on the state a fake collaborator records. A test that only checks a call happened, with no check of the result, is weak.

## When to use / NOT use

Use when someone needs **confidence that a feature's end-to-end tests are complete**, or a list of what is missing, before merging or shipping.

Do NOT use for: running the suites; reviewing a code diff; hunting latent behavioural bugs (**adversarial-bug-hunt**); writing the missing tests.

## Where the tests live (ground truth for Phase 3)

- **Automated suite:** `Tests/*.swift`, Swift Testing (`@Suite`, `@Test`, `#expect`), scheme `clearancekitTests`. CI runs it on every PR (`.github/workflows/pr-test.yml`: `xcodebuild test -scheme clearancekitTests -destination 'platform=macOS'`). Fakes are private nested types named `Fake…`; `Mock…` is not allowed.
- **Pipeline level (closest to end-to-end):** `FileAuthPipelineTests`, `FileAuthPipelineAuthorizationTests`, `ESInboundAdapterTests`, `ESTamperResistanceAdapterTests`, `FAAFilterInteractorTests`, `JailFilterInteractorTests`. These run the ES event → policy → respond chain with a fake ES API.
- **Domain:** `PolicyDecisionTests`, `ProcessTreeTests`, `AccessKindClassifierTests`, `BundleProtectionEvaluatorTests`, `JailRuleTests` and the other `Shared/` tests. Domain logic must be fully covered.
- **Persistence and policy:** `PolicyRepositoryTests`, `PolicyStoreTests`, `AllowlistStoreTests`, `JailStoreTests`, `EpochRatchetTests`, `ManagedLoaderTests`, the `Canonical…EncodingTests`.
- **Not automated:** the real Endpoint Security client, the installed system extension, XPC between the two binaries, the SwiftUI app and the MCP server. Coverage of those is manual (install the build and check events with the MCP `list_events` tool). Report any path that depends on these as "manual only", not as covered.

## What a "feature" decomposes into

```
{ SwiftUI screen states in clearancekit/ (Configure, Monitor) + MCP tools }
   × { XPC call through Shared/XPCProtocol.swift, validated by ConnectionValidator / AuthorizationGate }
      → { opfilter adapter: ESInboundAdapter / ESJailAdapter / XPCServer }
         × { FileAuthPipeline hot path vs slow path, FAAPolicy / GlobalAllowlist / JailRule decision,
             each deny reason, read vs write-only rules, primary vs secondary path, queue-full drop }
            × { respond call: allow / deny, cacheable flag, before the ES deadline }
               × { PolicyRepository / Database methods (real + fake pair), signing, EpochRatchet,
                   schema from DatabaseMigrations }
```

Each leaf maps to an **expected test**. The audit's job is to find leaves with no test, or a test that only asserts success.

---

## Phase 0 — scope the feature (ask first, do not guess)

Pin the surface before fanning out. Confirm with the user:

1. Which module or area, and which front-end entry points or routes?
2. Which handlers or endpoints are in scope? Which are explicitly out?
3. Are other clients (mobile, public API) in scope?
4. What counts as "done" — success paths only, or the full fault and validation set (default: full)?

Do not proceed to fan-out until the scope is confirmed. Record it; every later phase is bounded by it.

Also confirm the branch: an audit against a stale checkout produces findings that were fixed upstream. State the base ref in the report.

## Phase 1 — derive ALL routes (subagent, mutation-style, no scripts)

Dispatch a subagent that reads the **deployed** code path end to end and enumerates every branch as a distinct path. The enumeration is the mutation-testing intent: each branch is a mutant, and a real test must kill it. Two halves — do both.

### 1a. Server paths

- Every `if`, `switch case`, null-coalesce and early return in the handler → one path each.
- Every value of the handler's error enum or error type → the fault and validation set; **one test per error value**. An error value no test produces is a bare fault path.
- The validation order (ids exist → business rules → mutate) → each early return is its own path.
- Every permission level the endpoint is registered with → a distinct permission path, plus the **negative** case: an unregistered role must be refused. Check whether registration is additive and exact-match rather than a hierarchy. Add an IDOR row for every id taken from the request that must be scoped to the authenticated identity.
- CRUD matrix: Read (list with ≥2 rows, columns, empty state, not-found), Create (happy path, each required-field validation, format, business rule, cancel), Update (the validation matrix re-tested, partial edit, stale data), Delete (happy path, cancel, cascade or restriction).
- Data-access methods hit → each needs its own test **and** its fake or in-memory sibling must match. A method present in the real implementation but missing or divergent in the double is a coverage hole disguised as a green unit test.
- Any migration the feature depends on → is there an integration test that exercises the real columns?

### 1b. Front-end paths (the front end is its own path source, not a pass-through)

- **Template control flow** — every conditional and every empty branch of a loop = a rendered state to cover (shown, hidden, empty, loading, error).
- **Component and service branches** — every `if`, ternary, guard and early return that changes what renders or which request fires.
- **Routes and navigation** — every route, guard, deep link, redirect and query-parameter variant.
- **Form validation** — every client-side rule. Each is a path distinct from the server error values; both need coverage.
- **Server↔front-end error parity** — every error value the server can return must be mapped and rendered. Flag silently swallowed errors and missing in-flight or loading states.
- **API call sites** — each success and error handler is a path. A stale generated client means a whole error value may be unrepresented in the front-end types at all — that is a gap, not a pass.
- **Hidden and conditional dialogs** — confirm dialogs, alerts, overlays. A happy-path test never opens these, so they ship un-audited. Enumerate each.
- **Localisation and terminology** — if labels come from a terminology or i18n layer, a test asserting a hardcoded English label may be asserting the wrong oracle.
- **Assertion oracle** — every interactive element needs its test id and every page root its page-object marker. A path whose elements have no test id **cannot** be covered — record it as a gap with "add the test id first".

**Output of Phase 1 — path inventory table:**

| path id | layer (server/front-end) | trigger | expected outcome | assertion point (test id / error value) |
|---|---|---|---|---|

## Phase 2 — independent enumeration challenge (2nd subagent, withhold the code)

Dispatch a **fresh** subagent given ONLY the feature description or UI description (**withhold the code**) and have it derive the expected scenarios blind. Withholding the code stops it rationalising the code's own omissions. Fold any scenario it names that Phase 1 missed back into the inventory as its own row, marked `source: challenge`. This catches paths the code *forgot*, not just paths the code *has*.

## Phase 3 — enumerate existing tests (subagent)

Dispatch a subagent to locate every test touching the feature, across every suite listed above. For each test capture: which path or paths it exercises, and **what it actually asserts**.

Assertion strength:

- **Strong** — an end-to-end test that drives the real UI and asserts a rendered value at a known test id.
- **Weak** — asserts only database state, or only that the request succeeded inside a setup fixture (that is seeding, not verification), or a unit test standing in for a user-visible outcome.
- **Also check the silent gates** — a test can pass its assertions and still be masking a defect if the run leaves server exceptions or severe browser-console errors behind. A path "covered" by such a test is not covered.

**Output — test inventory table:**

| test class::method | project | path(s) covered | assertion strength (strong/weak) |
|---|---|---|---|

## Phase 4 — gap analysis (subagent)

Join the path inventory with the test inventory. A path row with **no** test, or only a **weak** test, is a gap. Classify and severity-rank:

**Gap types:** missing success path · missing validation (which error) · missing fault condition · missing permission audience or IDOR · weak assertion (database-only or success-flag-only) · missing UI state · missing client-side validation · server error with no front-end mapping · hidden dialog uncovered · missing test id (untestable as written) · fake versus real data-access divergence.

**Severity order (highest first):** uncovered fault/validation path > uncovered permission audience or IDOR > server error with no front-end mapping > weak or database-only assertion > missing edge, empty or hidden state.

## Output — the coverage verdict

Produce ONE coverage matrix and a summary:

| path | layer | covered? | test | assertion strength | gap type | severity |
|---|---|---|---|---|---|---|

- **Summary line:** paths total / covered / gaps, the base ref audited, and the honest verdict. If any fault or validation path is bare → the verdict is **NOT covered**, gaps listed at the top.
- **Handoff (only on the user's go):** dispatch the writing of the missing tests and the missing test ids. This skill never writes them itself.

## Subagent dispatch and fallback discipline

- Run Phases 1a, 1b and 3 as parallel subagents when the scope is large; aggregate into the single matrix.
- Keep Phase 2 a genuinely fresh context with the code withheld — a code-aware agent defeats the point.
- Any backgrounded subagent gets a backup wakeup — the completion notification is a single point of failure. When it fires, check the agent's real state before assuming failure.
- Stuck or looping in your own context two or three times → dispatch a clean-context subagent, do not thrash.

## Common mistakes

| Mistake | Reality |
|---|---|
| Auditing only the server handler | The front end has its own branches, form validation, guards and hidden dialogs — each is a path (Phase 1b). |
| "Happy path passes → covered" | One happy path is not coverage. Every user-visible state, and one test per error value. |
| Counting a setup fixture's success assertion as coverage | That is seeding, not verification. It does not prove the UI rendered the outcome. |
| Counting a unit test as end-to-end coverage | It proves the branch, not the wiring (registration, permissions, client, template). Track both columns. |
| Trusting the code's own scenario list | The code cannot reveal the path it forgot. Phase 2, with the code withheld, exists to catch that. |
| Ignoring permission registrations | Each registered role is a path, and each *unregistered* role needs a refusal test. |
| Skipping hidden dialogs and empty states | Conditionally hidden states never appear in a default run — enumerate and require each is reached and asserted. |
| Treating a green run as clean | The run also gates on zero server exceptions and zero severe front-end errors; check the diagnostics. |
| Reporting a cheerful ✅ with gaps underneath | Honest-state rule: a bare fault or validation path means NOT covered, gaps at the top. |

## Red flags — STOP

- About to write "fully covered" without having listed every error value and checked each has a test.
- Only produced a server path inventory (no routes, form validation or dialogs).
- The Phase 2 challenge agent was given the code — it cannot find omissions then.
- A gap classified below "weak assertion" when it is actually an uncovered fault condition or an IDOR path.
- Counted a path as covered when the element it needs has no test id.
- Backgrounded a subagent with no fallback timer.
- Did not name the base ref the audit ran against.
