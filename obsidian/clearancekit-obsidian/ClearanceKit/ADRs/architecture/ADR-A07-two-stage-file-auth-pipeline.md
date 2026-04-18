---
id: ADR-A07
domain: architecture
date: 2026-03-24
status: Accepted
---
# ADR-A07: Three-Stage File-Auth Pipeline

## Context

The original FAA implementation dispatched an unbounded `Task {}` from the ES callback for each `AUTH_OPEN` event. Under sustained file-access load this caused Swift concurrency thread starvation: cooperative threads were saturated with in-flight tasks, preventing the ES callback from returning `es_respond()` in time. macOS ES AUTH events have a hard kernel deadline (approximately 15 ms) after which the kernel auto-allows the event, silently bypassing policy.

Three commits define the pipeline: the initial two-stage replacement of unbounded Task dispatch (`edd6101`, 2026-03-24), the addition of a dedicated `postRespondQueue` for post-respond work (`eeb0ebc`, 2026-03-24), and the move of pipeline and repository construction to `main.swift` for transparent object-graph wiring (`614a794`, 2026-03-24).

## Options

1. **Keep unbounded Task dispatch** — simple code; collapses under load; ES deadline misses silently fail open.
2. **Actor with bounded inbox** — cooperative-thread-based; still subject to Swift executor saturation under sustained load; actors do not provide real-time scheduling guarantees.
3. **Explicit multi-stage pipeline with dedicated dispatch queues** — a hot-path serial queue always calls `es_respond()` before returning; a concurrent slow-path worker pool handles ancestry-dependent decisions; a serial post-respond queue does follow-up work without touching the ES deadline.

## Decision

The pipeline has three stages separated by two bounded queues.

**Submission (pre-Stage 1).** `ESInboundAdapter` receives ES events on the ES callback thread, marshals them onto `esAdapterQueue` (serial, QoS `.userInteractive`, `.never` autorelease), and calls `pipeline.submit()`. `submit()` attempts to enqueue the event into `eventBuffer` (`BoundedQueue`, capacity 1 024). If `eventBuffer` is full, the event is allowed immediately (fail-open) via `event.respond(true, false)`, ancestry is looked up synchronously, `postRespondHandler` is invoked, and the drop is counted in pipeline metrics. No further stages run for a dropped event.

**Stage 1 — Hot path** runs on `hotPathQueue` (serial, QoS `.userInteractive`). A dedicated loop waits on `eventSignal` and dequeues from `eventBuffer` one event at a time. For each event it: checks the global allowlist → evaluates path classification against current rules → calls `es_respond()`. For events that need no ancestry data (`noRuleApplies` or `processLevelOnly` with an empty ancestor allowlist), the full policy decision is made and `es_respond()` is called before any slow work begins. Events that need ancestry data are packaged as a `SlowWorkItem` and enqueued into `slowQueue` (`BoundedQueue`, capacity 256). If `slowQueue` is full, the event is allowed immediately (fail-open) and counted in metrics — `es_respond()` is still called in Stage 1.

**Stage 2 — Slow path** runs on `slowWorkerQueue` (concurrent, QoS `.userInitiated`). A serial dispatch loop waits on `slowSignal`, acquires `slowWorkerSemaphore` (value: 2, bounding concurrency to two workers at a time), dequeues a `SlowWorkItem`, and dispatches it onto `slowWorkerQueue`. Each worker: optionally waits for the process to appear in the process tree, looks up ancestors synchronously via `processTree.ancestors(of:)`, evaluates the full policy decision, and calls `es_respond()`. Ancestry lookups are synchronous calls on `ProcessTreeProtocol`; they are deferred to the slow path precisely because they may block.

**Stage 3 — Post-respond** runs on `postRespondQueue` (serial, QoS `.background`) via `PostRespondHandler`. It is invoked from all exit points in Stages 1 and 2 — after `es_respond()` has already been called — and performs: audit log write (`AuditLogger`) → TTY denial notification (`TTYNotifier`) → assembly of a `FolderOpenEvent` → invocation of the `onEvent` closure injected at wiring time in `main.swift`; the closure calls `server.handleEvent(_:)` to broadcast to all connected GUI clients. Because `es_respond()` has already returned before Stage 3 runs, it can take arbitrarily long without affecting the ES deadline.

All queues are constructed in `main.swift` (the single wiring point for the object graph) and injected as dependencies. Only `esAdapterQueue` carries `.never` autorelease frequency; it is set on that queue because it is where ES messages are retained and released at high throughput.

A correlation UUID threads through all three stages so audit log entries and GUI events can be matched to the originating ES event.

`XPCServer` is started before the process-tree scan at launch to reduce GUI connection latency. Once all dependencies are ready, `server.configure(_:)` is called with a `ServerContext` struct containing the full object graph.

## Consequences

- ES `es_respond()` is guaranteed to be called in Stage 1 or Stage 2, always before any post-respond work begins. Deadline misses from slow I/O or Swift executor saturation are eliminated.
- Post-respond work (logging, TTY notification, XPC broadcast) never blocks the ES callback thread or the hot-path queue.
- Two bounded queues with explicit fail-open overload policies make backpressure visible: under extreme load the system permits access rather than hanging, and both drop counts appear in pipeline metrics.
- The slow path limits concurrent ancestry-lookup workers to two via `slowWorkerSemaphore`, preventing runaway thread creation under bursty load.
- Constructing all queues and the pipeline in `main.swift` makes the full startup sequence and object graph visible in one place.
- Only `esAdapterQueue` uses `.never` autorelease frequency, scoped to where it is actually needed rather than applied globally.
