---
name: adversarial-bug-hunt
description: Use when the user wants to proactively hunt for latent / non-obvious bugs in a chosen slice of a codebase — race conditions, non-determinism, TOCTOU, ordering/timing bugs, lost updates, N+1 / sync-over-async, transaction-scope errors, date/time and timezone mistakes, swallowed exceptions, resource leaks, authorization and tenant-scoping holes, front-end async/state bugs — as opposed to reviewing style/conventions (that is a code-review skill) or checking test coverage (that is e2e-coverage-validation). Give it a SCOPE — a feature, an area/folder, a branch, a PR, a diff, or a set of files — and it fans out one adversarial Hunter subagent per bug-class, then a Skeptic pass that tries to DISPROVE each finding, then a Referee that issues REAL_BUG / NOT_A_BUG / MANUAL_REVIEW verdicts. Triggers — "hunt for bugs in X", "find race conditions in X", "what could go wrong in this feature/branch/PR", "adversarial review", "find the subtle bugs", "check this for concurrency / non-determinism", "bug hunt", "/bug-hunt", "assume this code is broken and find the failures". NOT for mechanical convention checks, NOT for coverage gaps, NOT for writing the fix.
---

# Adversarial bug hunt — assume the code is broken, then prove it

## Overview

One AI review pass is **non-deterministic and self-blinding**: the model latches onto the first bug class it sees (for example null-safety) and never looks for the others (for example race conditions). It also shares the blind spots of whatever model wrote the code. This skill defeats both by structure, not luck:

1. **Fan out** — a separate Hunter subagent per bug-class, each told to look for **only** its class, over an explicit scope. No agent can hook onto one class and starve the rest.
2. **Adversarial framing** — every Hunter is told to **assume the code is broken** and describe the **exact sequence that triggers failure** (not "possible concurrency issue").
3. **Skeptic** — a second agent tries to **disprove** each finding: find the lock, guard, transaction, database constraint or authorization check that already makes it safe. Kills noise.
4. **Referee** — an independent agent issues the binding verdict per finding: `REAL_BUG` / `NOT_A_BUG` / `MANUAL_REVIEW`.

**Core principle: a finding with no exact trigger sequence is not a finding.** Vague warnings are discarded, not reported.

It reports; it does **not** fix. Fixes are dispatched separately, on the user's say-so.

## Setting it up in your repo

This skill is stack-neutral. It gets sharper when you add your own facts:

- In [bug-classes.md](bug-classes.md), fill the **"Local hotspots"** line under each class with the real files, patterns and framework traps of your codebase — the job runner, the queue consumer, the caching layer, the ORM's lazy-loading trap, the generated client that goes stale.
- Add a "Stack facts every Hunter should know" paragraph at the top of `bug-classes.md`: language, concurrency model, data access, date/time library, front-end framework, anything generated.
- Delete the classes that cannot apply to your stack.

## When to use

- "Hunt for bugs in <feature/area/branch/PR>", "what could go wrong here", "find the subtle / latent bugs", "adversarial review", "check this for race conditions / non-determinism", "/bug-hunt".
- Before merging something risky (transactions, scheduled jobs, queue consumers, realtime fan-out, offline sync, timezone logic, state-heavy front-end code).
- After an intermittent or flaky symptom, to enumerate candidate mechanisms.

**Do NOT use for:**

- Style / convention compliance → a code-review skill.
- "Is this feature covered by tests" → **e2e-coverage-validation**.
- Writing the fix → your normal implementation flow. Never fix inline from here.

## Step 1 — Resolve the scope (do this first, always)

Turn the user's target into a concrete **file + diff set**. Pick the matching resolver:

| User gives you | How to resolve to files |
|---|---|
| A **branch** | `git diff --stat origin/<base>...<branch>` then read the changed files in full (not just the hunk) |
| A **PR** (number/url) | `gh pr diff <n> --name-only` → read those files; also `gh pr view <n>` for intent |
| A **diff** / "my changes" | `git diff --stat` (working tree) + `git diff origin/<base>...HEAD` |
| An **area / folder** | glob it |
| A **feature** (named, no branch) | grep the entry points — the handler/endpoint name, the client call, the route/component — then read outward to the collaborators |
| **Loose files** | read them plus one hop of their direct callers/callees (bugs live at boundaries) |

**Always read one hop out from the diff.** Concurrency, ordering and contract bugs live at the boundary between the changed code and its callers, not inside the hunk. A pure-diff view misses them.

For a server-side handler, "one hop" means at minimum: its data-access code (and any in-memory or fake implementation used by tests), its dependency-injection registration, its authorization registration, and the client and UI caller on the other side of the wire.

Record the resolved file list — it becomes the shared context every Hunter gets.

## Step 2 — Pick the bug-classes to hunt

Full taxonomy: **[bug-classes.md](bug-classes.md)** — read it before spawning, and hand each Hunter its class's section.

Default fan-out (drop classes that cannot apply to the scope — for example no front-end files means skip the async-ui class):

| Class | Hunt for |
|---|---|
| **concurrency** | race conditions, TOCTOU, lost updates, shared state, non-atomic compound operations |
| **non-determinism** | ordering assumptions, dictionary/set iteration order, unseeded time and random, parallel-order dependence |
| **date-time** | timezone and DST boundaries, wall-clock versus absolute-instant mix-ups, ambient clock reads |
| **transaction/data** | partial-failure corruption, missing transaction scope, non-idempotent retries, foreign-key order |
| **perf/latency** | N+1, sync-over-async, per-item external calls with no batching, work inside a transaction |
| **error-handling** | swallowed exceptions, over-broad catch, unhandled promise rejection, lost error context |
| **auth/tenant** | missing or too-broad authorization, intra-tenant IDOR, ids taken from the request not the identity, PII leaks |
| **async-ui** | front-end state and subscription races, leaks, stale reads, render-cycle errors |
| **boundary/contract** | caller and callee disagree on nullability, units or shape; off-by-one; dead branch |
| **resource-leak** | undisposed connections, sockets, listeners, file handles, timers, workers |

## Step 3 — Run the pipeline

**Preferred: the workflow script** — deterministic fan-out plus per-finding Skeptic and Referee, in one background run. Template: **[hunt-workflow.js](hunt-workflow.js)**. Copy it, set the scope file list and chosen classes at the top, run it with your orchestration tool. It pipelines, so each class's findings reach Skeptic and Referee as soon as that Hunter returns.

**Fallback (no workflow runner, or a tiny scope): dispatch subagents by hand** — one Hunter per class in a single message (parallel), collect findings, then one Skeptic message per finding, then judge yourself as Referee. Same three roles, manual.

Any backgrounded run gets a backup wakeup — the completion notification is a single point of failure.

### Hunter prompt (per class)

```
You are a bug HUNTER. Assume this code is BROKEN. Hunt ONLY for: <CLASS> bugs.
Scope (read these + one hop of their callers/callees):
<file list>
Stack context: <language / runtime / data access / framework>.

For EACH suspected bug, output JSON:
  - class: <CLASS>
  - file + line
  - trigger: the EXACT sequence of operations that makes it fail
            (e.g. "request A reads Foo at L20 between request B's delete at L44 and write at L46")
  - symptom: what a user or production would observe
  - evidence: the specific lines / cross-file dependency proving it
  - severity: critical | high | medium | low

RULES:
- No exact trigger sequence => DO NOT report it. Vague "possible issue" is noise.
- Only your class. Ignore style, naming, coverage, other bug classes.
- Prefer few high-confidence findings over many guesses.
```

### Skeptic prompt (per finding)

```
You are a SKEPTIC. Try to DISPROVE this bug claim. Read defensively:
find the lock, guard clause, database constraint, transaction scope, authorization
registration, single-threaded context, or framework guarantee that already makes it SAFE.
Claim: <finding JSON>
Files: <same scope>
Output: { disproven: true|false, counter_evidence: "<file:line + why safe>" }
Default to disproven=false only if you genuinely cannot find protection.
```

### Referee prompt (per surviving finding)

```
You are the REFEREE. Independent binding verdict. Re-read the cited code yourself.
Finding: <finding JSON>   Skeptic: <skeptic JSON>   Files: <scope>
Verdict: REAL_BUG | NOT_A_BUG | MANUAL_REVIEW  + one-line justification.
MANUAL_REVIEW only when the code genuinely cannot be judged from source alone.
```

## Step 4 — Report

Present only `REAL_BUG` and `MANUAL_REVIEW`, most-severe first. Per finding: file:line (clickable), class, exact trigger, symptom, verdict and justification. Name the classes hunted and any dropped as not-applicable, so the scope is honest. **Do not report `NOT_A_BUG`** except as a one-line count ("Skeptic/Referee killed N false positives").

Offer the next step: dispatch fixes (only on the user's go), or write a reproducing test. Never fix silently here.

## Common mistakes

- **One agent for all classes** — recreates the self-blinding this skill exists to prevent. One class per Hunter, always.
- **Diff-only scope** — misses boundary bugs. Read one hop out.
- **Reporting vague findings** — "might have a race" with no trigger sequence is noise. The Hunter rules already forbid it; do not relax them at report time.
- **Skipping the Skeptic** — Hunters over-report. Without the disprove pass you drown the user in false positives and they stop trusting the skill.
- **Fixing inline** — this skill reports. Fixes go through the normal feature flow on the user's say-so.
- **Using it for style** — that is a code-review skill. This is for behavioural correctness only.
