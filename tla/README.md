# TLA+ model — ES AUTH deadline miss

Formal specification of the EndpointSecurity AUTH event handling pipeline in
`opfilter`. The model demonstrates how a startup burst of AUTH events can
saturate Swift's cooperative thread pool, causing queued tasks to miss their
ES-imposed deadlines and triggering client termination (Code 2).

## Files

| File | Purpose |
|---|---|
| `ESAuthDeadline.tla` | TLA+ specification |
| `ESAuthDeadline.cfg` | TLC model-checker configuration |

## Running the model checker

```
tlc ESAuthDeadline -config ESAuthDeadline.cfg
```

TLC will report a violation of `ClientNeverTerminated` and print a
counterexample trace.

## The system under study

```
ES framework  ──▶  serial callback  ──▶  Task { }  ──▶  cooperative pool  ──▶  respond()
 (producer)         (dispatch)            (enqueue)      (bounded threads)      (consumer)
```

The ES framework delivers AUTH messages on a serial callback queue inside
`ESInboundAdapter`. The callback handler constructs a `FilterEvent` and calls
`interactor.handle(.fileAuth)`, which does:

```swift
Task { await self.handleFileAuth(event) }
```

This enqueues a task on Swift's cooperative thread pool and returns
immediately — the callback is non-blocking, so the ES callback queue is never
held up. However, the cooperative pool has a fixed number of threads (roughly
equal to CPU core count). Each task occupies a thread until `handleFileAuth`
returns.

Every AUTH message carries a `deadline` (a `mach_absolute_time` value). If
`opfilter` has not called `es_respond_*()` by that time, the ES framework
terminates the entire client process:

```
Termination Reason: Namespace ENDPOINTSECURITY, Code 2,
EndpointSecurity client terminated because it failed to respond
to a message before its deadline
```

## Counterexample trace (actual TLC output)

With the default configuration (`MaxEvents=3, PoolSize=1, EvalTime=2,
Deadline=4`), TLC finds that only **two** events are sufficient to trigger
the crash — the third is never even delivered:

```
Step 1  Init            clock=0  pool=0/1  queue=⟨⟩
Step 2  Deliver(1)      clock=0  pool=0/1  queue=⟨1⟩        event 1: queued at t=0
Step 3  Deliver(2)      clock=0  pool=0/1  queue=⟨1,2⟩      event 2: queued at t=0
Step 4  Schedule(1)     clock=0  pool=1/1  queue=⟨2⟩        event 1: running (pool full)
Step 5  Tick            clock=1
Step 6  Tick            clock=2
Step 7  Complete(1)     clock=2  pool=0/1  queue=⟨2⟩        event 1: responded
Step 8  Schedule(2)     clock=2  pool=1/1  queue=⟨⟩         event 2: running (started t=2)
Step 9  Tick            clock=3
Step 10 Tick            clock=4
Step 11 Miss(2)         clock=4  pool=0/1                    event 2: EXPIRED
                                                              alive := FALSE
```

Event 2 arrived at `t=0` with deadline `t=4`. It waited 2 ticks in the queue
(while event 1 held the pool thread), then started running at `t=2`. It needs
2 more ticks to complete (would respond at `t=4`), but the deadline check
fires at `t=4` while it is still running. The ES framework kills the client.

**Total time = queue wait (2) + eval time (2) = 4 = deadline. Miss.**

## Analysis

### Fundamental constraint

For `N` events arriving simultaneously on a pool of `P` threads, each holding
a thread for `T` ticks, event `k` (1-indexed) cannot start before:

```
queue_wait(k) = ⌊(k − 1) / P⌋ × T
```

It completes at:

```
complete(k) = queue_wait(k) + T = (⌊(k − 1) / P⌋ + 1) × T
```

The system survives only if every event completes before its deadline `D`:

```
(⌊(k − 1) / P⌋ + 1) × T  ≤  D    for all k = 1 … N
```

The critical event is the last one (`k = N`). Rearranging:

```
N  ≤  P × (D / T − 1) + 1
```

Any burst larger than this causes a deadline miss.

### Mapping to the real system

| Model parameter | Real system | Typical value |
|---|---|---|
| `PoolSize` | Swift cooperative thread pool | ≈ CPU cores (e.g. 8–12) |
| `EvalTime` (fast path) | `handleFileAuth` for no-rule / process-level events | < 1 ms |
| `EvalTime` (ancestry) | `waitForProcess` polling loop | up to `Deadline − 100 ms` |
| `Deadline` | `es_message_t.deadline` | ≈ 20 s (from crash timestamps) |
| `N` | AUTH events during startup burst | hundreds to thousands |

### Why `waitForProcess` is the amplifier

`waitForProcess` polls the process tree for a process identity that may not
yet have been inserted (because the FORK/EXEC event has not yet arrived, or
because the process pre-dates the ES client). The loop runs until the earlier
of:

- The process appears in the tree.
- `mach_absolute_time() >= deadline − 100 ms`.

For pre-existing processes (common during startup), the process will **never**
appear. Each such task holds a cooperative thread for nearly the full deadline
duration. With `P` threads occupied by ancestry-waiting tasks, all subsequent
tasks starve:

```
EvalTime ≈ Deadline − 100 ms ≈ 20 s

N_max = P × (D / T − 1) + 1
      ≈ P × (20 / 19.9 − 1) + 1
      ≈ P × 0.005 + 1
      ≈ 1  (for any practical P)
```

A **single** ancestry-waiting task per pool thread exhausts the system's
capacity. Any further event — even one that would complete in microseconds —
cannot start and will miss its deadline.

### Contrast: ESJailAdapter (no crash)

`ESJailAdapter` evaluates jail policy **synchronously** on the ES callback
queue and calls `es_respond_*()` before the callback returns. It never
dispatches AUTH work to the cooperative pool. This eliminates the queuing
delay entirely — each event is responded to within the callback, well before
any deadline.

```swift
// ESJailAdapter: synchronous respond on the callback queue
interactor.handleJailEventSync(event, jailRuleID: ruleID)

// ESInboundAdapter: async dispatch — subject to pool queuing delay
interactor.handle(Self.filterEvent(from: message, esClient: esClient))
//  └──> Task { await self.handleFileAuth(event) }
```

### What the model implies about fixes

The model identifies the root cause as **unbounded queuing delay on a bounded
thread pool under burst load**. Any correct fix must ensure that the time
between event arrival and response is bounded by the deadline, independent of
burst size. Possible approaches:

1. **Respond synchronously on the callback queue** (as `ESJailAdapter` does).
   Eliminates the pool bottleneck entirely. Requires that policy evaluation
   never blocks or performs I/O — which is already true for the fast path.

2. **Eliminate `waitForProcess`**. The ancestry polling loop is the primary
   thread-time amplifier. If ancestry data were populated before AUTH events
   arrive (e.g. by ensuring FORK/EXEC events are processed first, or by
   pre-seeding the tree), the ancestry path would be as fast as the
   process-level path.

3. **Bound the task queue depth**. If the number of in-flight tasks is
   capped at `P × (D / T − 1)`, no event can exceed its deadline. Excess
   events would need a synchronous fallback (e.g. allow without evaluation).

4. **Use a dedicated thread pool** (not the cooperative pool). A pool with
   enough threads to drain the burst within one deadline window. This trades
   memory for latency but does not fix the `waitForProcess` amplification.
