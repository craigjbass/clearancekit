# Bug-class taxonomy — hunt prompts

Hand each Hunter the section for its class. Each section = what to look for, the exact-trigger phrasing to demand, and a **Local hotspots** line for you to fill with your own codebase's real traps.

## Stack facts every Hunter should know

- **Language and targets.** Swift. Two binaries: `opfilter/` (Endpoint Security system extension, runs as root) and `clearancekit/` (SwiftUI GUI app, also hosts the MCP server). `Shared/` is pure domain code compiled into both.
- **Concurrency model.** Endpoint Security (ES) delivers AUTH messages on the ES client queue. `FileAuthPipeline` answers on a hot path when no ancestry is needed, and moves the event to a `BoundedQueue` slow path when a rule needs ancestry. Shared mutable state uses `OSAllocatedUnfairLock`. Ancestry lookups are lazy `@Sendable` closures.
- **The ES deadline.** Every AUTH message has a kernel deadline (`message.pointee.deadline`, mach time). A message that never gets `respondAuthResult` / `respondFlagsResult` before the deadline makes the kernel kill the client. Every code path that receives an AUTH message must respond exactly once. Messages kept past the callback are retained with `es_retain_message` and must be released.
- **Data access.** Hand-written SQLite in `opfilter/Database/Database.swift` with migrations in `DatabaseMigrations.swift`. Calls are synchronous. Policy rows are signed (`PolicySigner`), and `EpochRatchet` prevents rollback to an older signed state.
- **IPC.** `NSXPCConnection`. The protocol (`Shared/XPCProtocol.swift`) is shared by both binaries, so the installed extension and the app can be different versions. `ConnectionValidator` checks the peer by audit token.
- **Time.** ES deadlines use mach time (`MachTime`). Wall-clock `Date()` appears in `Database.swift`, `AuthorizationGate.swift`, `BundleCodesignCache.swift`, `PostRespondHandler.swift`, and in the app (`XPCClient.swift`, `MCPSessionStore.swift`). No clock is injected.
- **Generated code.** None. Contract drift happens between the app, the installed extension, and the signed database instead.
- **Tests.** Swift Testing in `Tests/`, with fakes named `Fake…`. `LiveEndpointSecurityAPI` sits behind the `EndpointSecurityAPI` protocol; a divergence between the fake and the live implementation is a boundary bug.
- **Not applicable.** No multi-tenant data, no web front end, no ORM. Read the `auth/tenant` class as "privilege boundary" and the `async-ui` class as "SwiftUI state".

---

## concurrency

Race conditions, TOCTOU (time-of-check/time-of-use), lost updates, shared-state conflicts, non-atomic compound operations, deadlock, starvation.

**Hunt for:**

- Check-then-act on shared state without a lock or a single atomic statement (`if (!Exists(id)) Add(...)` — two callers both pass the check).
- Read-modify-write on a database row with no optimistic-concurrency token or conditional `UPDATE … WHERE`.
- Static, singleton, or captured mutable state touched by concurrent requests.
- Fire-and-forget tasks not awaited, or background work mutating shared state.
- Compound "get count, then act on count" where another writer moves the count between the two.
- A "claim the work" query that lets two runners claim the same row.
- Retry or redelivery paths that let the same message run twice at once.

**Local hotspots:** `FileAuthPipeline` hot path versus slow path hand-off, `BoundedQueue`, `AllowlistState`, `PolicyRepository` rule swaps while events evaluate, `BundleCodesignCache`, the `AuthorizationGate` session store, the client set in `EventBroadcaster` / `MetricsBroadcaster`, `ESJailAdapter`, `PostRespondHandler` work after the response.

**Exact trigger demanded:** "request A does X at L\<n> between request B's Y at L\<m> and Z at L\<k>".

---

## non-determinism

Output depends on ordering, timing or environment that is not pinned.

**Hunt for:**

- A `SELECT` consumed as if ordered but with **no `ORDER BY`** (row order is undefined) — including "first row wins" logic and pagination with no stable tiebreak.
- Iterating a dictionary, set or lazy sequence and depending on order.
- Unseeded random, ambient id generation, or clock reads feeding logic or assertions.
- Culture-sensitive parsing or formatting (no invariant culture).
- Parallel accumulation into an order-sensitive structure.

**Local hotspots:** first-match rule selection in `Shared/FAAPolicy.swift` when rules overlap, `Database.swift` queries with no `ORDER BY`, canonical encoding for signing (`CanonicalRulesEncoding`, `CanonicalBundleUpdaterEncoding`) where iteration order changes the signature, `UUIDV5`.

**Exact trigger demanded:** "when the database returns rows in order B,A instead of A,B, line \<n> picks the wrong one".

---

## date-time

Timezone and DST boundaries, wall-clock versus absolute-instant mix-ups, ambient clock reads.

**Hunt for:**

- A platform date type used in domain code where the project's date library type belongs — and the conversion at the adapter boundary that silently assumes UTC.
- Ambient clock reads (`DateTime.Now`, `new Date()`, `time.Now()`) instead of the injected clock — untestable and non-deterministic.
- An absolute instant rendered or compared as if it were wall-clock local time, or a local date/time treated as an absolute point, with no timezone in between.
- Date arithmetic across a DST boundary done by adding a fixed duration where a zoned calendar add is meant (a "same time next day" shift becomes an hour out).
- Two different duration representations (seconds as integer versus a duration type) mixed in one calculation.
- Half-open versus closed interval slips on windows (end-exclusive versus end-inclusive).

**Local hotspots:** `AuthorizationGate` session expiry (wall clock, not monotonic), `MachTime.millisecondsToDeadline`, `BundleCodesignCache` entry age, `DispatchSourceMetricsTimer` and the `ESJailAdapter` 10-second timer, timestamps written by `Database.swift`, `MCPSessionStore` session lifetime.

**Exact trigger demanded:** "for an entry at 2026-03-29 01:30 Europe/London (DST spring-forward), line \<n> computes \<wrong value>".

---

## transaction/data

Partial-failure corruption, missing or wrong transaction scope, non-idempotent retries, foreign-key order violations.

**Hunt for:**

- Multiple writes (two aggregates, two tables) with no surrounding transaction — the first succeeds, the second throws, the database is left half-written.
- A retry path (queue redelivery, HTTP retry, user re-submit) that is not idempotent and runs the insert twice.
- Inserts in an order that violates foreign-key dependencies (child before parent).
- Side effects (email, push, queue publish, external API call) performed **before** the commit, or a commit that cannot be rolled back after the side effect fired.
- A handler returning success on a path where only part of the write completed.

**Local hotspots:** `Database.swift` writes that change rules and their signature in separate statements, `EpochRatchet` persistence, `ManagedPolicyLoader` / `ManagedAllowlistLoader` reloads that replace state, migration order in `DatabaseMigrations.swift`, preset rule UUIDs that the signature uses as keys.

**Exact trigger demanded:** "if line \<n> (second write) throws, rows from line \<m> are already committed, leaving \<inconsistent state>".

---

## perf/latency

N+1, sync-over-async, per-item external calls without batching, work done inside a transaction or lock.

**Hunt for:**

- A loop that issues one database query, HTTP call or email per iteration (N+1) — including a repository call inside a `foreach`.
- Fetching everything and filtering in memory what the query should filter — the whole table crosses the wire.
- Blocking on async work (`.Result`, `.Wait()`, `await` in a loop that should be parallel) causing thread-pool starvation or deadlock.
- An external call (email, SMS, push, object storage, geocoding, routing, LLM) per record with no batching.
- Heavy CPU or I/O work holding a transaction open.
- Unbounded growth: an append-only list or table with no cap or pruning.

**Local hotspots:** anything on the ES AUTH hot path before the respond call: ancestry lookups, codesign checks (`BundleCodesignCache`), SQLite reads, XPC sends, `AuditLogger` and `TTYNotifier` writes, per-event `EventBroadcaster` fan-out, and slow-queue saturation that drops events (`PIPELINE-DROP`, `SLOW-DROP`).

**Exact trigger demanded:** "for N=\<realistic count> records, this makes N sequential \<calls>, so total ≈ N × \<per-call> — pathological".

---

## error-handling

Swallowed exceptions, over-broad catch, unhandled promise rejection, lost error context.

**Hunt for:**

- `catch { }` or a catch that logs and then continues as if the call succeeded.
- A catch that returns a default or empty response, masking a real failure upstream.
- A handler returning a generic error value the caller cannot tell apart from a different failure.
- Front end: the success flag not checked, or the error list ignored and never mapped to anything the user sees; a subscription with no error arm; a promise neither awaited nor caught.
- Re-throw that drops the stack (`throw ex;` instead of `throw;`).

**Local hotspots:** AUTH paths that throw or return early without a respond call, the fail-open responses when a queue is full, `PolicySigner` verification failure paths, `Database` errors turned into empty rule sets, XPC reply blocks that are never called on the error path.

**Exact trigger demanded:** "when \<dependency> throws at L\<n>, the catch at L\<m> swallows it and the caller sees success with \<wrong/empty data>".

---

## auth/tenant

Authorization holes, intra-tenant IDOR, PII leakage.

**Hunt for:**

- An endpoint or handler registered at a **broader** permission level than it needs — especially anything reachable by a low-privilege or anonymous caller.
- A handler that takes an entity id **from the request** and acts on it without scoping to the authenticated identity — intra-tenant IDOR. Check whether registration is additive and exact-match rather than a hierarchy; one role's registration does not exclude another path reaching the same data.
- A read path that returns more rows than the caller's role should see (list, search, export and report endpoints are the classic offenders).
- PII (names, addresses, coordinates, contact details) in URLs, logs, error messages, or a response field the caller should not have.
- An outbound email, SMS or push recipient resolved from **request input** rather than from a stored record keyed by the authenticated identity.

**Local hotspots:** `ConnectionValidator` (audit token, team ID, signing ID checks), `AuthorizationGate` (user authorisation before a policy change), the MCP tools in `clearancekit/MCP/MCPTools.swift` that add, change and remove rules, precedence of managed (MDM) rules over user rules, tamper resistance in `ESTamperResistanceAdapter`, and paths or process names written to logs.

**Exact trigger demanded:** "a \<low-privilege role> session calls \<endpoint> with `<IdField>` belonging to another \<owner> at L\<n>; nothing checks ownership, so the response contains \<their data>".

---

## async-ui (front end)

State, subscription and render-cycle bugs.

**Hunt for:**

- A subscription with no bound lifetime (no unsubscribe, no teardown on destroy) → memory leak plus stale callbacks after destroy.
- Two calls racing where the **later-started** can resolve first and overwrite (latest-wins not enforced) — search and typeahead are the classic cases.
- Nested subscriptions where a higher-order operator belongs → ordering and cancellation bugs.
- Cache refresh races: a refresh fired after a mutation that resolves after a newer read, so the UI shows stale data; a cache read before its first populate.
- A reactive effect that writes state it also reads, or a computed value with a side effect → loops and render-cycle errors.
- A stale closure capturing an old component field inside a long-lived subscription.
- A component firing a request then navigating away before the response is handled.

**Local hotspots:** XPC callbacks in `clearancekit/App/XPCClient.swift` that change SwiftUI state off the main actor, the Monitor views (`Monitor/Events`, `Monitor/Metrics`, `Monitor/ProcessTree`), Configure screens that save and then reload policy, `MCPSessionStore` updates while `MCPAgentsView` renders.

**Exact trigger demanded:** "user types fast: request for 'ab' starts, then 'abc' starts; 'ab' resolves last and overwrites the 'abc' result at L\<n>".

---

## boundary/contract

Caller and callee disagree on nullability, units or shape; off-by-one; unreachable branch.

**Hunt for:**

- A **generated** client out of date with the server's request/response/error types — regeneration is usually a manual step, so drift is routine. A new error value the UI cannot render, or a removed field the UI still reads.
- An optional field on one side treated as guaranteed on the other (or a required field sent as absent).
- A query's column list versus the columns the table actually has (a mapping that compiles and fails at runtime).
- A fake or in-memory implementation whose behaviour diverges from the real one — tests pass, production does not.
- Off-by-one on ranges, pagination and index maths; inclusive versus exclusive slips.
- A condition that can never be true or false (dead branch) — often a real logic slip.
- Units mismatch (pence versus pounds, seconds versus milliseconds).

**Local hotspots:** `Shared/XPCProtocol.swift` with the app and the extension at different versions, the `NSSecureCoding` class allow-lists, ES C structure translation in `ESProcessRecord` / `ESInboundAdapter` (`es_string_token_t` has a length and is not NUL-terminated), `EndpointSecurityAPI` fake versus `LiveEndpointSecurityAPI`, path matching with `*`, `**` and trailing `/`, the secondary path on rename, link, clone and exchangedata events, SQL column lists in `Database.swift`.

**Exact trigger demanded:** "when the endpoint returns \<field> absent (allowed by the contract), the caller at L\<n> dereferences it → runtime error".

---

## resource-leak

Undisposed connections, sockets, listeners, handles, timers, workers.

**Hunt for:**

- A disposable resource created and never disposed (commands, readers, streams, per-call HTTP clients).
- A connection obtained outside the per-request scope, so it never returns to the pool.
- An event listener or DOM subscription added and never removed.
- A timer, interval, worker or websocket started and never cleared.
- A transaction opened on an early-return path that never commits or rolls back.

**Local hotspots:** `es_retain_message` without a matching `es_release_message` in `ESInboundAdapter` / `ESJailAdapter` (including the queue-full and drop paths), `sqlite3_prepare` without `sqlite3_finalize` in `Database.swift`, `DispatchSource` timers that are never cancelled, `NSXPCConnection` handlers that retain their owner, file handles in `AuditLogger`.

**Exact trigger demanded:** "each call to \<method> opens a \<resource> at L\<n> that is never closed; under load this exhausts \<pool/handles>".
