# TLA+ Formal Model — ES AUTH Pipeline

## What this models

The `ESAuthDeadline.tla` specification formally models the full synchronisation
architecture of the opfilter Endpoint Security AUTH event pipeline — both ES
clients, all queues, locks, and semaphores — to find conditions under which
AUTH events miss their kernel-enforced deadline, causing ES to terminate the
client (SIGKILL, Namespace ENDPOINTSECURITY, Code 2).

The ES kernel delivers every AUTH event to **both** ES clients independently.
Each client must respond within the deadline. The model checks this property
for both the FAA pipeline path (ESInboundAdapter → FileAuthPipeline) and the
jail inline path (ESJailAdapter).

## Architecture mapped

```
ES kernel
  ├─ ESInboundAdapter callback (esAdapterQueue, serial)
  │    └─ pipeline.submit(event)
  │         ├─ eventBuffer: BoundedQueue (capacity EB_Cap)
  │         │   full? → drop: respond(allow)
  │         │   ok?   → signal eventSignal
  │         └─ hotPathQueue (serial consumer, wakes on eventSignal)
  │              ├─ globallyAllowed / noRuleApplies → respond (H ticks)
  │              └─ ancestryRequired → slowQueue: BoundedQueue (capacity SQ_Cap)
  │                   full? → drop: respond(allow)
  │                   ok?   → signal slowSignal
  │                   └─ slowDispatchLoop (wakes on slowSignal)
  │                        └─ slowWorkerSemaphore.wait() [W permits]
  │                             └─ slowWorkerQueue (concurrent)
  │                                  └─ waitForProcess + evaluate (T ticks)
  │
  └─ ESJailAdapter callback (esJailAdapterQueue, serial)
       ├─ unjailed → respond(allow) immediately
       └─ jailed → check allowlist → checkJailPath → respond (J ticks)
```

## Synchronisation primitives inventory

The specification documents every synchronisation primitive in the opfilter
system extension. See the header comment in `ESAuthDeadline.tla` for the full
inventory. Summary:

### OSAllocatedUnfairLock instances (13)

| # | Lock | Type | Location | Model representation |
|---|------|------|----------|---------------------|
| 1 | `eventBuffer.storage` | `BoundedQueue.State` | `FileAuthPipeline` | Atomic enqueue/dequeue in FAASubmit/HotConsume |
| 2 | `slowQueue.storage` | `BoundedQueue.State` | `FileAuthPipeline` | Atomic enqueue/dequeue in HotConsume/SlowDispatch |
| 3 | `rulesStorage` | `[FAARule]` | `FilterInteractor` | Part of HotTicks duration |
| 4 | `allowlistStorage` | `[AllowlistEntry]` | `FilterInteractor` | Part of HotTicks / JailTicks duration |
| 5 | `ancestorAllowlistStorage` | `[AncestorAllowlistEntry]` | `FilterInteractor` | Part of HotTicks duration |
| 6 | `jailRulesStorage` | `[JailRule]` | `FilterInteractor` | Part of JailTicks duration |
| 7 | `processTree.storage` | `ProcessTree` state | `Shared` | Part of HotTicks / SlowTicks duration |
| 8 | `rulesLock` | `[JailRule]` | `ESJailAdapter` | Part of JailTicks duration |
| 9 | `jailedProcessesLock` | `[ProcessKey: UUID]` | `ESJailAdapter` | Part of JailTicks duration |
| 10 | `jailMetricsStorage` | `JailMetrics` | `FilterInteractor` | Not modelled (no deadline impact) |
| 11 | `metricsStorage` | `PipelineMetrics` | `FileAuthPipeline` | Not modelled (no deadline impact) |
| 12 | `PolicyRepository.storage` | policy state | `PolicyRepository` | Not modelled (management only) |
| 13 | `EventBroadcaster.storage` | clients + events | `EventBroadcaster` | Not modelled (post-respond only) |

### DispatchSemaphore instances (3)

| # | Semaphore | Initial value | Model representation |
|---|-----------|---------------|---------------------|
| 1 | `eventSignal` | 0 | Implicit: HotConsume enabled when eventBuffer non-empty |
| 2 | `slowSignal` | 0 | Implicit: SlowDispatch enabled when slowQueue non-empty |
| 3 | `slowWorkerSemaphore` | 2 (Workers) | Explicit: `workerBusyUntil` array (free slots = permits) |

### DispatchQueue instances (9)

| # | Queue | QoS | Type | Model representation |
|---|-------|-----|------|---------------------|
| 1 | `esAdapterQueue` | `.userInteractive` | serial | FAASubmit sequential submission |
| 2 | `esJailAdapterQueue` | `.userInteractive` | serial | JailConsume serialisation (`jailBusyUntil`) |
| 3 | `hotPathQueue` | `.userInteractive` | serial | HotConsume serialisation (`hotBusyUntil`) |
| 4 | `slowWorkerQueue` | `.userInitiated` | concurrent | SlowDispatch concurrent workers (`workerBusyUntil`) |
| 5 | `processTreeQueue` | `.userInitiated` | serial | Implicit in SlowTicks |
| 6 | `postRespondQueue` | `.background` | serial | Not modelled (post-deadline) |
| 7 | `xpcServerQueue` | `.userInitiated` | serial | Not modelled (GUI only) |
| 8 | `metricsQueue` | `.utility` | serial | Not modelled (reporting only) |
| 9 | `evictionQueue` | `.background` | serial | Not modelled (cleanup only) |

## Parameters

| Symbol | TLA+ constant | Real-world meaning |
|--------|---------------|--------------------|
| N | `NumEvents` | Number of AUTH events in a burst (delivered to both clients) |
| EB | `EB_Cap` | `eventBuffer` bounded queue capacity (default 1024) |
| SQ | `SQ_Cap` | `slowQueue` bounded queue capacity (default 256) |
| W | `Workers` | `slowWorkerSemaphore` permits (default 2) |
| D | `Deadline` | Ticks until ES kills the client |
| T | `SlowTicks` | Ticks a slow-path worker holds a permit |
| H | `HotTicks` | Ticks the serial hot path takes per event |
| J | `JailTicks` | Ticks a jailed event takes on the jail serial queue |

## Running the model checker

```bash
# Requires Java 11+
# Download TLC (one-time):
curl -sL -o tla2tools.jar \
  "https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"

# Run with the default configuration (expects violation):
java -cp tla2tools.jar tlc2.TLC ESAuthDeadline \
  -config ESAuthDeadline.cfg -workers auto
```

## TLC results

### Configuration 1: default `.cfg` — jail path deadline miss

```
NumEvents = 4, EB_Cap = 3, SQ_Cap = 2, Workers = 2,
Deadline = 5, SlowTicks = 3, HotTicks = 1, JailTicks = 2
```

**Result: Invariant `NoDeadlineMiss` VIOLATED on the jail path.**

Counter-example trace (all FAA events hot, all jail events jailed):

| tick | FAA path | jail path | notes |
|------|----------|-----------|-------|
| 0 | Submit e1–e3 to eventBuffer (e4 dropped: EB full) | Submit e1–e4 to jailQueue | |
| 0 | HotConsume e1 → respond at 1 | JailConsume e1 → respond at 2 | |
| 1 | HotConsume e2 → respond at 2 | (jail busy until 2) | |
| 2 | HotConsume e3 → respond at 3 | JailConsume e2 → respond at 4 | |
| 4 | FAA done | JailConsume e3 → respond at **6 > 5** ✗ | |

The jail adapter processes events serially. With 4 jailed events at `J=2` ticks
each, event 3 responds at tick 6, exceeding the deadline of 5. The jail
adapter's unbounded serial queue has no drop-on-full safety valve.

### Configuration 2: safe — within both path capacities

```
NumEvents = 2, EB_Cap = 3, SQ_Cap = 2, Workers = 2,
Deadline = 8, SlowTicks = 3, HotTicks = 1, JailTicks = 2
```

**Result: No error. Model checking completed.**

With 2 events: FAA path responds within deadline regardless of hot/slow
assignment. Jail path: even if both are jailed, responds at ticks 2 and 4,
both ≤ 8.

### Configuration 3: FAA path deadline miss (slow-path bottleneck)

```
NumEvents = 5, EB_Cap = 5, SQ_Cap = 3, Workers = 2,
Deadline = 7, SlowTicks = 3, HotTicks = 1, JailTicks = 1
```

**Result: Invariant `NoDeadlineMiss` VIOLATED on the FAA path.**

Counter-example trace (2 hot + 3 slow FAA, jail events safe at `J=1`):

| tick | eventBuffer | slowQueue | worker 1 | worker 2 | notes |
|------|-------------|-----------|----------|----------|-------|
| 0 | [1,2,3,4,5] | [] | idle | idle | all submitted |
| 1 | [2,3,4,5] | [] | idle | idle | e1 (hot) → respond 1 |
| 2 | [3,4,5] | [] | idle | idle | e2 (hot) → respond 2 |
| 2 | [4,5] | [3] | idle | idle | e3 (slow) → slow queue |
| 2 | [4,5] | [] | busy→5 | idle | SlowDispatch e3 |
| 3 | [5] | [4] | busy→5 | idle | e4 (slow) → slow queue |
| 3 | [5] | [] | busy→5 | busy→6 | SlowDispatch e4 |
| 4 | [] | [5] | busy→5 | busy→6 | e5 (slow) → slow queue |
| 5 | [] | [] | busy→8 | busy→6 | SlowDispatch e5 → respond **8 > 7** ✗ |

Event 5 waits in the hot path queue behind 4 events, then waits in the slow
queue for a semaphore permit. By the time a worker is free at tick 5, the 3-tick
processing pushes the response to tick 8, exceeding the deadline.

Jail path: all 5 events at `J=1` → responds at ticks 1–5, all ≤ 7. Safe.

## Capacity analysis

### FAA path

**Hot path throughput:** 1 event per `H` ticks (serial consumer). In `D` ticks
it can process `⌊D/H⌋` events. The hot path is rarely the bottleneck because
classification is cheap.

**Slow path throughput:** With `W` permits each held for `T` ticks, event `k`
(1-indexed, entering slow queue at tick `k × H`) finishes at
`k × H + wait_for_permit + T`. A miss occurs when this exceeds `D`.

**Drop safety:** Both `eventBuffer` (capacity `EB_Cap`) and `slowQueue`
(capacity `SQ_Cap`) drop and auto-allow events when full. Drops are safe —
they never miss a deadline. This bounds the blast radius under extreme load.

### Jail path

**Serial processing:** 1 event per `J` ticks (jailed) or immediate (unjailed).
No bounded queue, no drop behaviour. The GCD serial queue is unbounded.

**Deadline miss:** Event `k` (all jailed) responds at `k × J`. Miss when
`k × J > D`, i.e., `k > D/J`. With `J=1` tick and `D=10` (real-world ≈ 10s
deadline and sub-millisecond jail evaluation), the jail path can process ≈10,000
events per deadline window — safe in practice.

**Key finding:** The jail path lacks the bounded-queue safety valve of the FAA
path. Under extreme jailed-event volume with costly evaluation, it could miss
deadlines. In practice, jail evaluation (`checkJailPath`) is a simple prefix
match taking sub-millisecond, so this is not a concern at current volumes.

### Real-world parameters

| Parameter | Default | Real-world value |
|-----------|---------|------------------|
| `EB_Cap` | 1024 | `eventBuffer` capacity in `FileAuthPipeline` |
| `SQ_Cap` | 256 | `slowQueue` capacity in `FileAuthPipeline` |
| `Workers` | 2 | `slowWorkerSemaphore` initial value in `main.swift` |
| `H` | ~0.01 ms | Hot path classification (lock acquire + rule lookup) |
| `T` | up to ~9.9 s | `waitForProcess` spin-wait + policy evaluation |
| `D` | ~10 s | ES kernel deadline per AUTH event |
| `J` | ~0.01 ms | Jail inline evaluation (lock acquire + prefix match) |

## Comparison with previous model

The previous TLA+ model modelled the Swift cooperative thread pool directly:

| Aspect | Previous model | Current model |
|--------|---------------|---------------|
| **Scope** | FAA path only | Both FAA and jail paths |
| **Queuing** | Unbounded pending queue | Two bounded queues (FAA) + unbounded serial queue (jail) |
| **Processing** | Thread pool (P threads, direct dispatch) | Serial hot path → bounded slow workers (FAA); serial inline (jail) |
| **Back-pressure** | None (all events queued) | Drop + auto-allow when full (FAA); none (jail) |
| **Synchronisation** | Thread pool only | All 13 locks, 3 semaphores, 9 queues documented |
| **Failure mode** | Starvation: event cannot start | FAA: queuing delay; Jail: serial accumulation |
| **Safety valve** | None | Drop-on-full at both FAA queue stages |

The key insight from the current model: **deadline misses are still possible**
on the FAA path when many slow events arrive in a burst, but the **blast radius
is bounded** by queue capacities and drop behaviour. The jail path is safe in
practice due to sub-millisecond evaluation but lacks a structural safety valve.
