# TLA+ Formal Model — ES AUTH Pipeline

## What this models

The `ESAuthDeadline.tla` specification formally models the 2-stage bounded-queue
pipeline that processes Endpoint Security AUTH events in opfilter. The goal is to
determine under what conditions AUTH events miss their kernel-enforced deadline,
causing ES to terminate the client (SIGKILL, Namespace ENDPOINTSECURITY, Code 2).

## Architecture mapped

```
ES kernel callback (serialised per client)
  └─ ESInboundAdapter callback
       └─ pipeline.submit(event)
            ├─ eventBuffer: BoundedQueue (capacity EB_Cap)
            │   full? → drop: respond(allow), shed load
            │   ok?   → signal eventSignal
            │
            └─ hotPathQueue (serial consumer, wakes on eventSignal)
                 ├─ Dequeue from eventBuffer
                 ├─ Classify:
                 │   ├─ globally allowed / no rule applies → respond (H ticks)
                 │   └─ ancestry required → enqueue to slowQueue
                 │
                 └─ slowQueue: BoundedQueue (capacity SQ_Cap)
                      full? → drop: respond(allow), shed load
                      ok?   → signal slowSignal
                      │
                      └─ slowDispatchLoop (wakes on slowSignal)
                           └─ slowWorkerSemaphore.wait() [W permits]
                                └─ slowWorkerQueue (concurrent)
                                     ├─ waitForProcess spin-wait (T ticks)
                                     ├─ evaluate policy → respond
                                     └─ slowWorkerSemaphore.signal()
```

**Key design elements:**

1. **Bounded queues with drop-on-full:** When `eventBuffer` or `slowQueue` is
   full, the event is immediately allowed and dropped. This guarantees
   back-pressure — the pipeline never accumulates unbounded work.

2. **Serial hot path:** A single `hotPathQueue` consumer classifies events and
   resolves most of them without touching the slow path. Only events requiring
   ancestry lookup are forwarded to the slow queue.

3. **Bounded slow worker pool:** `slowWorkerSemaphore` (default value 2) limits
   concurrent slow-path workers. Each worker holds a permit for the full
   duration of `waitForProcess` + evaluation. The dispatch loop blocks on the
   semaphore, so work items queue in `slowQueue` until a permit is available.

## Parameters

| Symbol | TLA+ constant | Real-world meaning |
|--------|---------------|--------------------|
| N | `NumEvents` | Number of AUTH events in a burst |
| EB | `EB_Cap` | `eventBuffer` bounded queue capacity (default 1024) |
| SQ | `SQ_Cap` | `slowQueue` bounded queue capacity (default 256) |
| W | `Workers` | Slow-path semaphore permits (default 2) |
| D | `Deadline` | Ticks until ES kills the client |
| T | `SlowTicks` | Ticks a slow-path worker holds a permit |
| H | `HotTicks` | Ticks the serial hot path takes per event |

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

### Configuration 1: burst exceeds pipeline capacity (default `.cfg`)

```
NumEvents = 5, EB_Cap = 4, SQ_Cap = 2, Workers = 2,
Deadline = 6, SlowTicks = 3, HotTicks = 1
```

**Result: Invariant `NoDeadlineMiss` VIOLATED.**

Counter-example trace (4 hot events + 1 slow event):

| tick | action | eventBuffer | slowQueue | worker 1 | worker 2 | notes |
|------|--------|-------------|-----------|----------|----------|-------|
| 0 | Submit e1–e4 | [1,2,3,4] | [] | idle | idle | |
| 0 | HotConsume e1 (hot) | [2,3,4] | [] | idle | idle | respond e1 at tick 1 |
| 0 | Submit e5 | [2,3,4,5] | [] | idle | idle | EB full after this |
| 1 | HotConsume e2 (hot) | [3,4,5] | [] | idle | idle | respond e2 at tick 2 |
| 2 | HotConsume e3 (hot) | [4,5] | [] | idle | idle | respond e3 at tick 3 |
| 3 | HotConsume e4 (hot) | [5] | [] | idle | idle | respond e4 at tick 4 |
| 4 | HotConsume e5 (slow) | [] | [5] | idle | idle | enqueued to slow path |
| 4 | SlowDispatch e5 | [] | [] | busy→7 | idle | responds at **tick 7 > Deadline 6** ✗ |

Event 5 spends ticks 0–4 queued behind hot events in the eventBuffer. The
serial hot path processes one event per tick, so e5 reaches the slow path at
tick 4. The slow worker takes 3 ticks (waitForProcess + evaluate). Total
response time: 7 ticks > 6-tick deadline.

### Configuration 2: within capacity (safe)

```
NumEvents = 3, EB_Cap = 4, SQ_Cap = 2, Workers = 2,
Deadline = 8, SlowTicks = 3, HotTicks = 1
```

**Result: No error. Model checking completed.**

With 3 events and D=8: even if all 3 are slow, the hot path drains them at
ticks 1, 2, 3. Workers pick up events 1 and 2 immediately (finish at ticks 4
and 5). Event 3 gets a permit at tick 4 when worker 1 finishes, and responds at
tick 7 ≤ 8. All events meet the deadline.

### Configuration 3: large buffer with few workers

```
NumEvents = 8, EB_Cap = 8, SQ_Cap = 4, Workers = 2,
Deadline = 10, SlowTicks = 4, HotTicks = 1
```

**Result: Invariant `NoDeadlineMiss` VIOLATED.**

Even with large buffers, the bottleneck is the slow worker pool. Events
accumulate in the slow queue and the last ones cannot be processed before their
deadline expires.

## Capacity analysis

### Hot path throughput

The serial consumer processes one event per `H` ticks. In `D` ticks it can
process `⌊D/H⌋` events. Events beyond `EB_Cap` are dropped (safe). The hot
path is rarely the bottleneck because `H` is small (classification is cheap).

### Slow path throughput

With `W` worker permits each held for `T` ticks:

```
Slow capacity in one deadline window = W × ⌊D/T⌋
```

But events do not all enter the slow queue simultaneously — they are serialised
through the hot path. Event `k` (1-indexed) enters the slow queue at tick
`k × H`. It must finish by tick `D`. So the constraint is:

```
k × H + wait_for_permit + T ≤ D
```

The wait for a permit depends on when the next worker becomes free. In the
worst case (all slow), the first `W` events get permits immediately and the
remaining events wait for the earliest completion.

### Drop safety

Dropped events are auto-allowed, so they never miss a deadline. The bounded
queues guarantee that the pipeline cannot accumulate more than `EB_Cap + SQ_Cap`
events. This is a deliberate trade-off: under extreme load, some events are
allowed without policy evaluation rather than risking a deadline miss that would
terminate the entire ES client.

### Real-world parameters

| Parameter | Default | Real-world value |
|-----------|---------|------------------|
| `EB_Cap` | 1024 | `eventBuffer` capacity in `FileAuthPipeline` |
| `SQ_Cap` | 256 | `slowQueue` capacity in `FileAuthPipeline` |
| `Workers` | 2 | `slowWorkerSemaphore` initial value in `main.swift` |
| `H` | ~0.01 ms | Hot path classification (lock acquire + rule lookup) |
| `T` | up to ~9.9 s | `waitForProcess` spin-wait + policy evaluation |
| `D` | ~10 s | ES kernel deadline per AUTH event |

With `Workers = 2` and `T ≈ D`:
- Only 2 slow events can be in-flight simultaneously.
- Event 3 entering the slow path at any point will finish at `entry_tick + T`,
  which easily exceeds `D` if `entry_tick > 0`.

The bounded queues and drop behaviour ensure that excess events are shed rather
than queued indefinitely. This prevents the SIGKILL crash that occurred in the
previous unbounded `Task`-based architecture, at the cost of allowing some
events without evaluation during burst overload.

## Comparison with previous model

The previous TLA+ model (`ESAuthDeadline.tla` prior to this revision) modelled
the Swift cooperative thread pool directly:

| Aspect | Previous model | Current model |
|--------|---------------|---------------|
| **Queuing** | Unbounded pending queue | Two bounded queues with drop-on-full |
| **Processing** | Thread pool (P threads, direct dispatch) | Serial hot path → bounded slow worker pool |
| **Back-pressure** | None (all events queued) | Explicit: drop + auto-allow when full |
| **Bottleneck** | Thread pool saturation (P+1 slow events) | Slow worker semaphore + hot path serialisation |
| **Failure mode** | Starvation: event cannot start | Queuing delay: event enters slow path too late |
| **Safety valve** | None | Drop-on-full at both queue stages |

The key insight from the current model: **deadline misses are still possible**
when many slow events arrive in a burst, but the **blast radius is bounded** by
the queue capacities and the drop behaviour prevents cascading failure.
