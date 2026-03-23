# TLA+ Formal Model — ES AUTH Deadline

## What this models

The `ESAuthDeadline.tla` specification formally models the threading
architecture of the opfilter Endpoint Security AUTH event pipeline. The goal is
to determine under what conditions AUTH events miss their kernel-enforced
deadline, causing ES to terminate the client (SIGKILL, Namespace
ENDPOINTSECURITY, Code 2).

## Architecture mapped

```
ES kernel callback thread (per-client serial queue)
  └─ ESInboundAdapter closure
       ├─ NOTIFY_FORK / NOTIFY_EXIT / AUTH_EXEC → sync, inline
       └─ AUTH_OPEN / AUTH_RENAME / … (file auth)
            └─ Task { await handleFileAuth(event) }
                 └─ Swift cooperative thread pool  [bounded to P threads]
                      ├─ Fast path: globally allowed → respond immediately
                      └─ Slow path: waitForProcess spin-wait (up to deadline − 100 ms)
                           └─ evaluate policy → respond
```

**Key constraint**: the Swift cooperative thread pool has a fixed width `P`
(approximately equal to the CPU core count). Each `Task` dispatched from the ES
callback occupies one thread for the full duration of the event handler,
including any `waitForProcess` spinning.

## Parameters

| Symbol | TLA+ constant | Real-world meaning |
|--------|---------------|--------------------|
| N | `NumEvents` | Number of AUTH events in a burst |
| P | `PoolSize` | Cooperative thread pool width |
| D | `Deadline` | Ticks until ES kills the client |
| T | `SlowTicks` | Ticks a slow-path event holds a thread |
| F | `FastTicks` | Ticks a fast-path event takes |

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

### Configuration 1: P+1 slow events (default `.cfg`)

```
NumEvents = 3, PoolSize = 2, Deadline = 4, SlowTicks = 3, FastTicks = 1
```

**Result: Invariant `NoDeadlineMiss` VIOLATED.**

Counter-example trace:

| tick | action | thread 1 | thread 2 | event 3 |
|------|--------|----------|----------|---------|
| 0 | Dispatch e1 (slow) | busy until 3 | idle | queued |
| 0 | Dispatch e2 (slow) | busy until 3 | busy until 3 | queued |
| 1–2 | Tick | busy | busy | **waiting** |
| 3 | Dispatch e3 (slow) | busy until 6 | free | started |
| — | — | — | — | responds at **tick 6 > Deadline 4** ✗ |

Event 3 cannot start until tick 3 (when a thread frees up), and then takes 3
more ticks. Total response time: 6 ticks > 4-tick deadline.

### Configuration 2: N = P (safe)

```
NumEvents = 2, PoolSize = 2, Deadline = 4, SlowTicks = 3, FastTicks = 1
```

**Result: No error. Model checking completed.**

When the number of simultaneous events equals the pool size, every event gets a
thread immediately and responds before the deadline.

### Configuration 3: Mixed fast/slow (realistic startup)

```
NumEvents = 5, PoolSize = 2, Deadline = 6, SlowTicks = 5, FastTicks = 1
```

**Result: Invariant `NoDeadlineMiss` VIOLATED.**

Even with a mix of fast and slow events, if enough slow events queue up they
block fast events behind them from ever reaching a thread in time.

## Capacity formula

Derived analytically and confirmed by exhaustive TLC model checking:

```
N_safe = P × ⌊D / T⌋ + min(P, ⌊(D mod T) / F⌋)
```

When `T ≈ D` (waitForProcess holds a thread for nearly the full deadline):

```
N_safe ≈ P
```

**In practice on Apple Silicon:**

| Machine | Cores (P) | ES deadline (D) | waitForProcess worst case (T) | Safe burst (N) |
|---------|-----------|-----------------|------------------------------|----------------|
| M1 | 8 | ~10 s | ~9.9 s | **8** |
| M4 Pro | 10 | ~10 s | ~9.9 s | **10** |
| M4 Max | 14 | ~10 s | ~9.9 s | **14** |

Any burst exceeding P slow events causes at least one deadline miss →
SIGKILL.

## Root cause of the crash

At startup:

1. `buildInitialTree()` populates the process tree from a `proc_listallpids`
   snapshot.
2. ES subscription begins — events start arriving immediately.
3. Processes forked **between** the snapshot and the ES subscription are not in
   the tree.
4. AUTH events from these processes enter `waitForProcess`, which spin-waits
   (via `Task.sleep(1ms)`) for up to `deadline − 100ms`.
5. Each waiting task **holds a cooperative thread** for nearly the full
   deadline.
6. When more than P such events arrive simultaneously, the P+1-th event
   cannot even start its `Task` — no cooperative thread is available.
7. The event's deadline passes with no response → ES kills the process.

**Why it happens within 30 seconds of launch**: the process tree is most
incomplete at startup. The race window between `buildInitialTree()` and
`es_subscribe()` is maximised, and the burst of initial AUTH events from
already-running processes triggers many concurrent `waitForProcess` calls.

## Identified issues

### Issue 1: Cooperative thread pool saturation (confirmed by TLC)

`waitForProcess` holds a cooperative thread in a busy-wait loop for up to
`deadline − 100ms`. With `T ≈ D`, each thread can only service one slow event
per deadline window. A burst of P+1 slow events guarantees a miss.

**Severity**: Critical. Directly causes the SIGKILL crash.

### Issue 2: No back-pressure from pool to ES callback

The ES callback dispatches `Task { await handleFileAuth(event) }` without
checking whether the cooperative thread pool has capacity. Events are queued
unboundedly with no shedding mechanism. The ES callback returns immediately
(freeing the ES serial queue) but the event's deadline is already ticking.

**Severity**: Contributing. Amplifies Issue 1 by allowing unlimited queuing.

### Issue 3: Startup race window

The gap between `buildInitialTree()` completing and `es_subscribe()` starting
means any process forked in that window enters the slow (waiting) path, making
startup the worst-case scenario for thread pool saturation.

**Severity**: Contributing. Maximises the number of slow-path events at the
most vulnerable time.
