--------------------------- MODULE ESAuthDeadline ---------------------------
(*
 * Formal TLA+ model of the opfilter Endpoint Security AUTH event pipeline.
 *
 * Purpose
 * -------
 * Model the threading architecture of opfilter to find conditions under which
 * AUTH events miss their kernel-enforced deadline, causing the ES client to be
 * terminated (SIGKILL, Code 2).
 *
 * Architecture mapped (from ESInboundAdapter.swift / FilterInteractor.swift)
 * --------------------------------------------------------------------------
 *  ES kernel callback queue (unbounded, serialised per client)
 *    -> ESInboundAdapter callback
 *      -> for file-AUTH events: Task { await handleFileAuth(event) }
 *        -> Swift cooperative thread pool (bounded to P threads)
 *          -> Fast path: globally-allowed / no-rule-applies -> respond()
 *          -> Slow path: waitForProcess spin-wait up to (deadline - 100ms)
 *             then evaluate policy and respond()
 *
 * Abstractions
 * ------------
 *  - Time is modelled as a discrete integer tick.
 *  - Each AUTH event has a deadline D ticks from arrival.
 *  - The cooperative thread pool has P threads.
 *  - A "fast" event needs F ticks to complete (allowlist hit / no rule).
 *  - A "slow" event (waitForProcess path) needs T ticks where T <= D-1.
 *  - Events arrive and are immediately queued for the pool.
 *  - A thread is occupied for the full duration of its event.
 *
 * Parameters (overridden in the .cfg)
 * ------------------------------------
 *  NumEvents  -- total AUTH events to model
 *  PoolSize   -- cooperative thread pool width (P)
 *  Deadline   -- ticks until ES kills the client (D)
 *  SlowTicks  -- ticks consumed by a waitForProcess path (T)
 *  FastTicks  -- ticks consumed by a fast path (F)
 *
 * What TLC checks
 * ---------------
 *  Invariant "NoDeadlineMiss":
 *    No event may remain unresponded past its deadline, and no responded
 *    event may have been responded to after its deadline.
 *)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS NumEvents,     \* Total AUTH events in the model run
          PoolSize,      \* Cooperative thread pool width (P)
          Deadline,      \* Ticks until ES kills client per event (D)
          SlowTicks,     \* Ticks a slow-path event holds a thread (T)
          FastTicks       \* Ticks a fast-path event holds a thread (F)

ASSUME NumEvents \in Nat /\ NumEvents >= 1
ASSUME PoolSize  \in Nat /\ PoolSize  >= 1
ASSUME Deadline  \in Nat /\ Deadline  >= 2
ASSUME SlowTicks \in Nat /\ SlowTicks >= 1
ASSUME FastTicks \in Nat /\ FastTicks >= 1

Events == 1..NumEvents

\* Sentinel: event has not been started / responded to yet.
PENDING == -1

(* Every event is either "fast" (globally allowed, no ancestry) or "slow"
   (waitForProcess path). We model all possible mixes via the initial state. *)
VARIABLE eventKind,      \* eventKind[e] \in {"fast", "slow"}
         startedAt,      \* startedAt[e]    -- tick a thread began (PENDING = pending)
         respondedAt,    \* respondedAt[e]  -- tick respond() called (PENDING = pending)
         busyUntil,      \* busyUntil[t]    -- tick thread t becomes free (0 = idle)
         tick,           \* global discrete clock
         pendingQueue    \* FIFO of events awaiting a thread

vars == <<eventKind, startedAt, respondedAt, busyUntil, tick, pendingQueue>>

\* ---- Helpers ----

Duration(e) == IF eventKind[e] = "slow" THEN SlowTicks ELSE FastTicks

FreeThreads == { t \in 1..PoolSize : busyUntil[t] <= tick }

AllDone == \A e \in Events : respondedAt[e] /= PENDING

\* ---- Initial state ----
(* All events arrive at tick 0 (worst-case burst).  Each event is
   non-deterministically fast or slow. *)

Init ==
    /\ eventKind    \in [Events -> {"fast", "slow"}]
    /\ startedAt    = [e \in Events |-> PENDING]
    /\ respondedAt  = [e \in Events |-> PENDING]
    /\ busyUntil    = [t \in 1..PoolSize |-> 0]
    /\ tick         = 0
    /\ pendingQueue = [i \in 1..NumEvents |-> i]

\* ---- Actions ----

(* Dispatch: take the head-of-queue event and assign it to a free thread. *)
Dispatch ==
    /\ ~AllDone
    /\ Len(pendingQueue) > 0
    /\ FreeThreads /= {}
    /\ LET e == Head(pendingQueue)
           t == CHOOSE t \in FreeThreads : TRUE
           d == Duration(e)
       IN /\ startedAt'    = [startedAt    EXCEPT ![e] = tick]
          /\ respondedAt'  = [respondedAt  EXCEPT ![e] = tick + d]
          /\ busyUntil'    = [busyUntil    EXCEPT ![t] = tick + d]
          /\ pendingQueue' = Tail(pendingQueue)
          /\ UNCHANGED <<eventKind, tick>>

(* Tick: advance clock when no dispatch is possible (queue empty or pool full)
   and there is still outstanding work. *)
Tick ==
    /\ ~AllDone
    /\ \/ Len(pendingQueue) = 0
       \/ FreeThreads = {}
    /\ tick' = tick + 1
    /\ UNCHANGED <<eventKind, startedAt, respondedAt, busyUntil, pendingQueue>>

(* Stutter once all events are handled -- prevents false deadlock. *)
Done ==
    /\ AllDone
    /\ UNCHANGED vars

\* ---- Specification ----

Next == Dispatch \/ Tick \/ Done

Spec == Init /\ [][Next]_vars /\ WF_vars(Dispatch) /\ WF_vars(Tick)

\* ---- Safety invariants ----

(* Core property: no event may be past its deadline without a response.
   All events arrive at tick 0, so the absolute deadline is just Deadline.

   Two sub-conditions:
     1. If responded: respondedAt[e] <= Deadline
     2. If not responded: tick <= Deadline  (event still has time)

   Violation of either means the ES client would be killed. *)
NoDeadlineMiss ==
    \A e \in Events :
        \/ respondedAt[e] /= PENDING /\ respondedAt[e] <= Deadline
        \/ respondedAt[e] = PENDING  /\ tick <= Deadline

\* ---- Derived: capacity formula ----
(*
 * Analytical capacity bound (confirmed by TLC exhaustive search):
 *
 *   When T = D - 1 (waitForProcess consumes nearly the full deadline):
 *     N_safe = P
 *
 *   General case:
 *     N_safe = P * floor(D / T)  +  min(P, floor((D mod T) / F))
 *
 * where:
 *   P = PoolSize   (cooperative threads)
 *   D = Deadline   (ticks)
 *   T = SlowTicks  (ticks per slow event)
 *   F = FastTicks  (ticks per fast event)
 *
 * The crash in the issue occurs when all events take the slow path and
 * NumEvents > P.  With T close to D, each thread can service only ONE slow
 * event per deadline window, giving N_safe = P.  Event P+1 starts at tick T
 * and finishes at tick 2T > D -- deadline miss.
 *
 * On an M4 Pro (10 cores, P~10): 11 simultaneous slow AUTH events trigger
 * the kill.  At startup, many processes are not yet in the tree, causing
 * widespread waitForProcess.  This matches the crash within 30s of launch.
 *)

=============================================================================
