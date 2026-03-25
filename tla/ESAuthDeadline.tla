--------------------------- MODULE ESAuthDeadline ---------------------------
(*
 * Formal TLA+ model of the opfilter Endpoint Security AUTH event pipeline.
 *
 * Purpose
 * -------
 * Model the 2-stage bounded-queue pipeline architecture of opfilter to find
 * conditions under which AUTH events miss their kernel-enforced deadline,
 * causing the ES client to be terminated (SIGKILL, Code 2).
 *
 * Architecture mapped (from FileAuthPipeline.swift / FilterInteractor.swift)
 * --------------------------------------------------------------------------
 *  ES kernel callback (serialised per client)
 *    -> ESInboundAdapter callback
 *      -> pipeline.submit(event)
 *        -> eventBuffer: BoundedQueue (capacity EB_Cap)
 *           full? -> drop: respond(allow), shed load
 *           ok?   -> signal eventSignal
 *        -> hotPathQueue (serial consumer, wakes on eventSignal)
 *           dequeue from eventBuffer
 *           classify:
 *             globally allowed / no rule applies -> respond immediately (H ticks)
 *             process-level only, no ancestor allowlist -> evaluate inline (H ticks)
 *             ancestry required -> enqueue to slowQueue
 *        -> slowQueue: BoundedQueue (capacity SQ_Cap)
 *           full? -> drop: respond(allow), shed load
 *           ok?   -> signal slowSignal
 *        -> slowDispatchLoop (wakes on slowSignal)
 *           slowWorkerSemaphore.wait() (bounded to W permits)
 *           dispatch to slowWorkerQueue (concurrent)
 *             waitForProcess spin-wait up to (deadline - 100ms) (T ticks)
 *             evaluate policy -> respond
 *             slowWorkerSemaphore.signal()
 *
 * Abstractions
 * ------------
 *  - Time is modelled as a discrete integer tick.
 *  - Each AUTH event has a deadline D ticks from arrival.
 *  - The hot path processes one event per H ticks (serial consumer).
 *  - A slow-path worker holds a semaphore permit for T ticks.
 *  - Events arrive in a burst at tick 0 (worst case).
 *  - Bounded queues drop and auto-allow events when full.
 *  - A dropped event is safe (responded to immediately).
 *
 * Parameters (overridden in the .cfg)
 * ------------------------------------
 *  NumEvents    -- total AUTH events to model
 *  EB_Cap       -- eventBuffer bounded queue capacity
 *  SQ_Cap       -- slowQueue bounded queue capacity
 *  Workers      -- slow-path semaphore permits (W)
 *  Deadline     -- ticks until ES kills the client per event (D)
 *  SlowTicks    -- ticks a slow-path worker holds a permit (T)
 *  HotTicks     -- ticks the hot path takes to classify + optionally respond (H)
 *
 * What TLC checks
 * ---------------
 *  Invariant "NoDeadlineMiss":
 *    Every event is either responded to within its deadline, dropped (auto-allowed
 *    within the same tick), or still has time remaining.
 *)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS NumEvents,     \* Total AUTH events in the burst
          EB_Cap,        \* eventBuffer capacity
          SQ_Cap,        \* slowQueue capacity
          Workers,       \* Slow-path semaphore permits (W)
          Deadline,      \* Ticks until ES kills client per event (D)
          SlowTicks,     \* Ticks a slow-path worker occupies a permit (T)
          HotTicks       \* Ticks the serial hot path consumer takes per event (H)

ASSUME NumEvents \in Nat /\ NumEvents >= 1
ASSUME EB_Cap    \in Nat /\ EB_Cap    >= 1
ASSUME SQ_Cap    \in Nat /\ SQ_Cap    >= 1
ASSUME Workers   \in Nat /\ Workers   >= 1
ASSUME Deadline  \in Nat /\ Deadline  >= 2
ASSUME SlowTicks \in Nat /\ SlowTicks >= 1
ASSUME HotTicks  \in Nat /\ HotTicks  >= 1

Events == 1..NumEvents

NONE == -1

(*
 * eventKind:    "hot" (resolved on hot path) or "slow" (needs ancestry / waitForProcess).
 * respondedAt:  tick the event was responded to (NONE = not yet).
 * dropped:      TRUE if the event was dropped due to a full queue (auto-allowed).
 * eventBuffer:  FIFO sequence of event IDs (bounded by EB_Cap).
 * slowQueue:    FIFO sequence of event IDs (bounded by SQ_Cap).
 * hotBusyUntil: tick the serial hot path consumer becomes free.
 * workerBusyUntil: per-worker-slot tick it becomes free.
 * tick:         global discrete clock.
 * submitted:    number of events submitted to eventBuffer so far.
 *)
VARIABLE eventKind,
         respondedAt,
         dropped,
         eventBuffer,
         slowQueue,
         hotBusyUntil,
         workerBusyUntil,
         tick,
         submitted

vars == <<eventKind, respondedAt, dropped, eventBuffer, slowQueue,
          hotBusyUntil, workerBusyUntil, tick, submitted>>

\* ---- Helpers ----

AllDone == \A e \in Events : respondedAt[e] /= NONE \/ dropped[e]

FreeWorkers == { w \in 1..Workers : workerBusyUntil[w] <= tick }

\* ---- Initial state ----
(* All events arrive at tick 0 (worst-case burst). Each event is
   non-deterministically hot or slow. *)

Init ==
    /\ eventKind      \in [Events -> {"hot", "slow"}]
    /\ respondedAt    = [e \in Events |-> NONE]
    /\ dropped        = [e \in Events |-> FALSE]
    /\ eventBuffer    = <<>>
    /\ slowQueue      = <<>>
    /\ hotBusyUntil   = 0
    /\ workerBusyUntil = [w \in 1..Workers |-> 0]
    /\ tick           = 0
    /\ submitted      = 0

\* ---- Actions ----

(* Submit: an event arrives from the ES callback and enters eventBuffer.
   If the buffer is full the event is dropped (auto-allowed immediately). *)
Submit ==
    /\ submitted < NumEvents
    /\ LET e == submitted + 1
       IN \/ /\ Len(eventBuffer) < EB_Cap
             /\ eventBuffer' = Append(eventBuffer, e)
             /\ dropped' = dropped
          \/ /\ Len(eventBuffer) >= EB_Cap
             /\ dropped' = [dropped EXCEPT ![e] = TRUE]
             /\ eventBuffer' = eventBuffer
    /\ submitted' = submitted + 1
    /\ UNCHANGED <<eventKind, respondedAt, slowQueue, hotBusyUntil,
                    workerBusyUntil, tick>>

(* HotConsume: the serial hot path consumer dequeues one event, classifies it,
   and either responds immediately (hot) or enqueues it to the slow queue.
   Takes H ticks of wall-clock time. *)
HotConsume ==
    /\ Len(eventBuffer) > 0
    /\ hotBusyUntil <= tick
    /\ LET e == Head(eventBuffer)
       IN /\ eventBuffer' = Tail(eventBuffer)
          /\ hotBusyUntil' = tick + HotTicks
          /\ IF eventKind[e] = "hot"
             THEN /\ respondedAt' = [respondedAt EXCEPT ![e] = tick + HotTicks]
                  /\ slowQueue' = slowQueue
                  /\ dropped' = dropped
             ELSE IF Len(slowQueue) < SQ_Cap
                  THEN /\ slowQueue' = Append(slowQueue, e)
                       /\ respondedAt' = respondedAt
                       /\ dropped' = dropped
                  ELSE /\ dropped' = [dropped EXCEPT ![e] = TRUE]
                       /\ slowQueue' = slowQueue
                       /\ respondedAt' = respondedAt
    /\ UNCHANGED <<eventKind, workerBusyUntil, tick, submitted>>

(* SlowDispatch: the slow dispatch loop dequeues a work item and assigns it
   to a free worker slot. The worker holds the permit for T ticks. *)
SlowDispatch ==
    /\ Len(slowQueue) > 0
    /\ FreeWorkers /= {}
    /\ LET e == Head(slowQueue)
           w == CHOOSE w \in FreeWorkers : TRUE
       IN /\ slowQueue' = Tail(slowQueue)
          /\ respondedAt' = [respondedAt EXCEPT ![e] = tick + SlowTicks]
          /\ workerBusyUntil' = [workerBusyUntil EXCEPT ![w] = tick + SlowTicks]
    /\ UNCHANGED <<eventKind, dropped, eventBuffer, hotBusyUntil, tick, submitted>>

(* Tick: advance clock when no action can make progress and work remains. *)
Tick ==
    /\ ~AllDone
    /\ \/ submitted >= NumEvents
       \/ Len(eventBuffer) >= EB_Cap
    /\ \/ Len(eventBuffer) = 0
       \/ hotBusyUntil > tick
    /\ \/ Len(slowQueue) = 0
       \/ FreeWorkers = {}
    /\ tick' = tick + 1
    /\ UNCHANGED <<eventKind, respondedAt, dropped, eventBuffer, slowQueue,
                    hotBusyUntil, workerBusyUntil, submitted>>

(* Stutter once all events are handled -- prevents false deadlock. *)
Done ==
    /\ AllDone
    /\ UNCHANGED vars

\* ---- Specification ----

Next == Submit \/ HotConsume \/ SlowDispatch \/ Tick \/ Done

Spec == Init /\ [][Next]_vars /\ WF_vars(Submit) /\ WF_vars(HotConsume)
             /\ WF_vars(SlowDispatch) /\ WF_vars(Tick)

\* ---- Safety invariants ----

(* Core property: no event may be past its deadline without a response.
   All events arrive at tick 0, so the absolute deadline is just Deadline.

   Three sub-conditions:
     1. If dropped: safe (auto-allowed in the same tick).
     2. If responded: respondedAt[e] <= Deadline.
     3. If neither: tick <= Deadline (event still has time). *)
NoDeadlineMiss ==
    \A e \in Events :
        \/ dropped[e]
        \/ respondedAt[e] /= NONE /\ respondedAt[e] <= Deadline
        \/ respondedAt[e] = NONE  /\ ~dropped[e] /\ tick <= Deadline

(* Liveness: every event is eventually either responded to or dropped. *)
AllEventsHandled == <>[]AllDone

\* ---- Derived: capacity analysis ----
(*
 * The pipeline has two bounded queues and a bounded worker pool.
 * Load shedding (drop-on-full) ensures that an event is either:
 *   (a) responded to through the pipeline, or
 *   (b) auto-allowed and dropped at the point of queue saturation.
 *
 * Dropped events are safe (responded immediately), so the only way to
 * miss a deadline is if an event enters the pipeline but the pipeline
 * cannot process it before its deadline expires.
 *
 * Hot path throughput:
 *   The serial consumer processes 1 event per H ticks.
 *   In D ticks it can process floor(D / H) events.
 *   Events beyond EB_Cap are dropped (safe).
 *
 * Slow path throughput:
 *   With W worker permits and each worker holding for T ticks:
 *   At most W events can be in-flight simultaneously.
 *   In D ticks, each permit can service floor(D / T) events.
 *   Total slow capacity in one deadline window: W * floor(D / T).
 *   Events beyond SQ_Cap are dropped (safe).
 *
 * A deadline miss occurs when an event sits in the slow queue waiting
 * for a permit longer than (D - H_accumulated - T) ticks, where
 * H_accumulated is the time spent waiting in the eventBuffer + being
 * classified on the hot path.
 *
 * The worst case is NumEvents slow events with EB_Cap >= NumEvents:
 *   Hot path drains one event every H ticks.
 *   Event k enters slow queue at tick k * H.
 *   Worker assignment depends on semaphore availability.
 *   Event k finishes at tick (k * H) + wait_for_permit + T.
 *   If this exceeds D, deadline miss.
 *
 * With the default parameters (EB_Cap=4, SQ_Cap=2, Workers=2, H=1,
 * T=3, D=6, NumEvents=5):
 *   5 slow events: hot path drains at ticks 1,2,3,4,5.
 *   Workers 1,2 take events at ticks 1,2 -> finish at 4,5.
 *   Event 3 enters slow queue at tick 3, gets permit at tick 4 -> finishes 7 > 6.
 *   VIOLATION expected.
 *)

=============================================================================
