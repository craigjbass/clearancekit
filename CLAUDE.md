# ClearanceKit — Developer Guide

## Before ANY work — settle the working tree first

Do this **before** you read code for a task, plan, edit a file, run a build, or start an audit. It comes before every other step, including exploration.

1. Fetch the base branch this repo ships from: `git fetch origin main`.
2. Measure: `git rev-parse --abbrev-ref HEAD`, `git rev-list --left-right --count origin/main...HEAD`, `git status --porcelain`.
3. **Classify the request**, then follow that branch. Read-only and write requests get different treatment.

**Read-only** — the deliverable is an answer and nothing changes: explain, describe, summarise, review, audit, find, trace, compare, diagnose, "why does…", "where is…".

**Write** — the deliverable is a change: fix, add, implement, refactor, rename, remove, migrate, generate, deploy, "make it…".

**Ambiguity means write.** "Look at the login bug" is read-only; "look at the login bug and sort it" is write. A read-only task that turns into a write asks the question at that moment, before the first edit.

### Read-only: do not ask. State one line and start.

There is nothing to decide — the working copy is what the user is asking about.

```
Read-only request, so using the local working copy as it stands.
FACT: on <branch>, 0 behind / 2 ahead of origin/main.
```

Add a **WARNING** line only where it changes what the answer is worth:

```
WARNING: this branch is 5 commits behind origin/main — findings may already be fixed upstream.
WARNING: 3 uncommitted files in the tree, so this is not what is on any branch.
```

Nothing extra when the branch is current and the tree is clean. Do not offer to update the branch.

### Write: ask with the interface's question control, not with text

Use `AskUserQuestion` (or the harness's equivalent structured-choice control). **Do not print the numbered list as prose when a question control exists** — a text list scrolls away, is easy to answer ambiguously, and does not show the user that the session is blocked on them. Print options as text only where the harness has no such control.

- **Header:** `Working tree`
- **Question:** `What working tree? <branch> is <N> commits behind main.`

| # | Option | Commands |
|---|---|---|
| 1 | New branch from latest `main` | `git fetch origin main && git checkout -b <work branch> origin/main` |
| 2 | Pull latest `main` and work here | `git pull --ff-only` on the current branch |
| 3 | Work on the existing files as they are | Change nothing about the branch. State the behind-count once and carry on. |
| 4 | New work tree from latest `main` | `git worktree add <path> -b <work branch> origin/main`, then work in that path |
| 5 | Other | The user names the branch, ref or arrangement. Do what they say. |

Ask it once per task, not every turn, in fixed order. Wait for the answer — do not pick a default and continue. Uncommitted changes are a second question in the same message: name the files.

**An option that fails is not an answer.** `git pull --ff-only` refuses on a diverged branch; `git checkout -b` fails on an existing name. Print the exact error, print `git log --oneline origin/main..HEAD`, and ask again. Never choose a merge, rebase or reset yourself to make the option work.

Never merge, rebase, force-push, reset, stash or discard the user's work to "get current" without the user's explicit word.

Report the state in the first message of the task: `FACT: on <branch>, 0 behind / 3 ahead of origin/main.`

## How to write (applies to EVERY response and document)

Write all text you produce for the user in **ASD-STE100 (Simplified Technical English)**. This covers chat replies, explanations, hand-overs, status updates, commit and PR bodies, specs, docs, skill files, code comments, issues and chat messages.

Rules:

- **One word, one meaning.** Use the same word for the same thing every time. Do not vary words for style: "start" stays "start" — never "kick off", "initiate", "spin up", "fire up".
- **Use short, common words.** Write "use" not "utilise", "fix" not "remediate", "before" not "prior to".
- **One instruction per sentence.** Instruction sentences about 20 words; descriptive sentences about 25.
- **Active voice, present tense.** Name the actor: "the operation writes the row", not "the row is written".
- **No ambiguous pronouns.** Repeat the noun: "the migration failed", not "it failed".
- **No noun stacks longer than three words.**
- **No idioms, metaphors, jokes-as-explanation, or vague verbs.** Do not write "handles", "deals with", "takes care of", "stuff". Say what the code does.
- **Warnings first.** Put a caution before the instruction it applies to.
- **Quote technical content exactly.** Identifiers, paths, commands, error text, SQL and code blocks stay verbatim.
- **Never mention the style in your output.** No disclaimer, no header, no footer. This rule is the one place the standard is named.
- **No editorialising. Report the fact, do not dramatise it.** Give the fact and the measured impact, then stop. No superlatives about a finding, no contrast frames ("that is the difference between X and Y"), no restatement for emphasis, no graded asides.
- **No confession, no preamble. Use a label.** Start the line with one label, then the fact: `FACT:` `CONCERN:` `WARNING:` `MISTAKE:` `BLOCKED:` `UNKNOWN:` `REGRESSION:` `IMPLEMENTATION FAULT:` `EXISTING BUG:`.
  - Fixed shape: `LABEL: <one sentence that says what is wrong>: <what you will change to fix it>.` Then make the fix. Do not explain how you found it, do not rate the severity, do not summarise after the fix.
  - **Never cite the rule you broke.** Banned in any wording: "that is the exact failure the rule exists to prevent", "this is why the rule says X", "the doc warns about this".
  - Banned openers in any wording: "I have to be honest", "full transparency", "I should flag that", "I want to be upfront", "I need to own this", "in the interest of honesty".
- **Never tell the user they were right, and never grade their wording.** Banned: "You were right", "Good catch", "Correct", "Exactly", "Fair point". When the user corrects you, make the change and state the new fact with a label.
- **Never narrate your own behaviour, and never announce the answer before you give it.** Banned: "Let me check", "Here is what I found", "Getting the actual detail", "Now doing it correctly". Do the research, then open with `FACT:`.
- **The word "live" means Production only.** For anything else write "present", "visible", "still there", "reproduces", or name the environment.
- **Never write "wedged", "hung", "stuck".** Name the observed symptom: "no output since `<time>`", "the endpoint returns HTTP 500", "exited with code `<n>`". If you did not check, write `UNKNOWN:`.
- **Never write "landed".** Name the exact state: "Pushed to `<branch>`", "PR open", "Merged to `main`", "Deployed to staging", "Deployed to Production".
- **Never write "cut" about a branch.** Write "branched from `main`", not "cut from `main`". Same for "cut a ticket" and "cut a release": write "created the issue", "tagged the release".
- **Use the plain verb.** "the fix sets `-1`", not "the fix stamps `-1`". Repeating a plain word is correct.

**Fixed word list.** Use the left column every time. Never use the right column. Add a row when a new drift word appears.

| Use | Never use |
| --- | --- |
| set, write | stamp, brand, imprint, bake in, slap on |
| present, visible, still there, reproduces | live (unless Production), in the wild, alive, in play |
| start | kick off, initiate, spin up, fire up |
| run | drive, exercise, hammer, throw at |
| fix | remediate, address, sort out, patch up |
| check | interrogate, eyeball, poke at, sanity-check |
| change | tweak, massage, mutate (unless the real API term) |
| fail, failure | blow up, fall over, die, go pop |
| show | paint, dress up, light up |
| no output, exited with code `<n>`, returns HTTP 500 | wedged, hung, stuck, jammed |
| FACT:, CONCERN:, WARNING:, MISTAKE: | I owe you, to be honest, full transparency, I should flag |
| (delete the sentence) | you were right, good catch, exactly, fair point, correct |
| (state the fix only) | that is the exact failure X exists to prevent, this is why the rule says |
| (do the research, then FACT: …) | let me check, here is what I found, now doing it correctly |
| merged to `main`, deployed to staging | landed, shipped (unless Production), went out |
| branched from `main`, created the issue, tagged the release | cut from, cut a branch, cut a ticket, cut a release |

**Exceptions — do NOT apply ASD-STE100 to:** UI copy and translation strings, mock-ups and design content, marketing or customer-facing text, seed and test data. Write those to suit the product and its audience.

## Working discipline (NON-NEGOTIABLE)

Override default instinct. Every turn.

- **NEVER give time or effort estimates.** No "heavy", "~mins", "big job", "could take a while" — anywhere. State *what* you are doing, never how long.
- **NEVER stop partway because it "feels like a checkpoint".** Finish what was asked. The only legitimate stop is a genuine blocker (missing credential, a user-only decision, an external system down). "I've done a lot" is not a reason.
- **NEVER hand-edit schema / create tables / drop constraints** to work around a missing-object or FK error. Schema lives in the migration tool. Missing object = stale database; re-run migrations. FK violation = fix the migration, repository or seed. Destructive migrations need explicit user instruction.
- **NEVER report success — "passing", "deployed", "✅" — when anything is failing.** A non-2xx, red CI check, failed test, thrown error, or tripped error gate = FAILURE. Fix it, or report it plainly at the TOP: what failed, the exact status/error, what you tried. Partially broken is reported as broken.
- **NEVER bless an absurd timing.** A runtime out of proportion to the work is a defect (N+1, sync-over-async, un-batched per-item calls, work inside a transaction). Fix it or surface it with the measured number.

## Background-task monitoring

When starting any long-running background job — a subagent, a background shell command, a workflow — ALWAYS also schedule a backup wakeup that fires regardless of completion notifications. Completion notifications sometimes fail to arrive; without a backup the work stops until the user prompts.

- Backup wakeup at roughly `expected_runtime * 1.5`, capped at 1800s. Parallel agents: use the slowest.
- **On wake:** check whether the task is still running (output file last-modified time). Silent for more than 5 minutes, or past the expected runtime → read the last 200 lines, identify the last call, name the cause in your next response, then stop and retry with a tighter timeout if it is safe.
- After diagnosing, always write a follow-up improvement (shorter timeout, better error message, a fake instead of a real network call) so the same stop cannot happen twice.
- Do not wait silently with no backup. Do not ask the user "is it done yet".

## Releases

**Never create GitHub releases or draft releases.** The build pipeline creates immutable releases automatically. Creating releases manually (including drafts) interferes with this process.

Editing the **description/notes** of an existing release is fine — use `gh release edit <tag> --notes "..."`. Only the creation of releases is forbidden.

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
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS'
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

## Preset and rule UUIDs

Every `FAARule` and `AppPreset` requires a stable UUID that must never change after the rule ships — the database signing system uses it as a key.

**Always generate new UUIDs with `uuidgen`:**

```bash
uuidgen
# → e.g. B0267342-C6B1-4348-8412-C188DF765752
```

Never hand-craft UUID strings.

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

## Skills (`.claude/skills/`)

- **adversarial-bug-hunt** — hunt latent bugs in a scope through Hunter → Skeptic → Referee subagents. Stack facts and hotspots for opfilter and the app are in `bug-classes.md`. Triggers: "find bugs in X", "race conditions", "what could go wrong", "/bug-hunt". Reports only; never fixes.
- **e2e-coverage-validation** — list every path through a feature and the tests that cover each one, then rank the gaps. Paths that depend on the real ES client, XPC or the SwiftUI app are reported as manual only. Triggers: "validate coverage", "find test gaps". Read-only.

## End-of-turn rule

After any work touching files, end with a one-line git note:
`Pushed to <branch>.` · `Committed locally, not pushed.` · `Uncommitted changes.` · `No file changes.`
