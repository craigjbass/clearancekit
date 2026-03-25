--------------------------- MODULE ESAuthDeadline ---------------------------
(*
 * Formal TLA+ model of the opfilter Endpoint Security AUTH event pipeline.
 *
 * Purpose
 * -------
 * Model the full synchronisation architecture of opfilter — both ES clients,
 * all queues, locks, and semaphores — to find conditions under which AUTH
 * events miss their kernel-enforced deadline, causing the ES client to be
 * terminated (SIGKILL, Code 2).
 *
 * The ES kernel delivers every AUTH event to BOTH ES clients independently.
 * Each client must respond within the deadline. This model checks that
 * property for both the FAA pipeline path and the jail inline path.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * SYNCHRONISATION PRIMITIVES INVENTORY
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * --- OSAllocatedUnfairLock instances (13) ---
 *
 * Modelled explicitly as atomic queue operations:
 *  1. eventBuffer.storage      BoundedQueue<FileAuthEvent>
 *     → FAASubmit (tryEnqueue), HotConsume (dequeue)
 *  2. slowQueue.storage        BoundedQueue<SlowWorkItem>
 *     → HotConsume (tryEnqueue), SlowDispatch (dequeue)
 *
 * Modelled implicitly through action durations (HotTicks / SlowTicks / JailTicks):
 *  3. rulesStorage             [FAARule]            FilterInteractor
 *     → read on hot path classification (part of HotTicks)
 *  4. allowlistStorage         [AllowlistEntry]     FilterInteractor
 *     → read on FAA hot path + jail path (part of HotTicks / JailTicks)
 *  5. ancestorAllowlistStorage [AncestorAllowlistEntry] FilterInteractor
 *     → read on hot path classification (part of HotTicks)
 *  6. jailRulesStorage         [JailRule]           FilterInteractor
 *     → read in handleJailEventSync (part of JailTicks)
 *  7. processTree.storage      ProcessTree state
 *     → read on hot + slow path for ancestry (part of HotTicks / SlowTicks)
 *     → written on processTreeQueue for fork/exec/exit
 *  8. ESJailAdapter.rulesLock  [JailRule]
 *     → read in jail callback to match signatures (part of JailTicks)
 *  9. ESJailAdapter.jailedProcessesLock [ProcessKey: UUID]
 *     → read/write in jail callback for process tracking (part of JailTicks)
 *
 * Not on critical path (post-respond / management — no deadline impact):
 * 10. jailMetricsStorage       JailMetrics          FilterInteractor
 * 11. metricsStorage           PipelineMetrics      FileAuthPipeline
 * 12. PolicyRepository.storage  policy state
 * 13. EventBroadcaster.storage  GUI clients + event ring buffer
 *
 * --- DispatchSemaphore instances (3) ---
 *
 *  1. eventSignal (initial: 0)
 *     → modelled: FAASubmit signals, HotConsume waits
 *       (implicit in action enablement — HotConsume requires non-empty eventBuffer)
 *  2. slowSignal (initial: 0)
 *     → modelled: HotConsume signals, SlowDispatch waits
 *       (implicit in action enablement — SlowDispatch requires non-empty slowQueue)
 *  3. slowWorkerSemaphore (initial: Workers)
 *     → modelled: workerBusyUntil array (free slots = available permits)
 *
 * --- DispatchQueue instances (9) ---
 *
 *  1. esAdapterQueue       (.userInteractive, serial)
 *     → modelled: FAASubmit sequential submission (one event per action)
 *  2. esJailAdapterQueue   (.userInteractive, serial)
 *     → modelled: JailConsume serialisation (jailBusyUntil)
 *  3. hotPathQueue         (.userInteractive, serial)
 *     → modelled: HotConsume serialisation (hotBusyUntil)
 *  4. slowWorkerQueue      (.userInitiated, concurrent)
 *     → modelled: SlowDispatch concurrent dispatch (workerBusyUntil array)
 *  5. processTreeQueue     (.userInitiated, serial)
 *     → modelled: implicit in SlowTicks (tree lookup included in duration)
 *  6. postRespondQueue     (.background, serial)
 *     → not modelled (post-deadline, no safety impact)
 *  7. xpcServerQueue       (.userInitiated, serial)
 *     → not modelled (GUI communication, no deadline impact)
 *  8. metricsQueue         (.utility, serial)
 *     → not modelled (metrics reporting only)
 *  9. evictionQueue        (.background, serial)
 *     → not modelled (background cleanup)
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Architecture mapped
 * -------------------
 *  ES kernel
 *    ├─ ESInboundAdapter callback (esAdapterQueue, serial)
 *    │    └─ pipeline.submit(event)
 *    │         ├─ eventBuffer: BoundedQueue (capacity EB_Cap)
 *    │         │   full? → drop: respond(allow)
 *    │         │   ok?   → signal eventSignal
 *    │         └─ hotPathQueue (serial consumer, wakes on eventSignal)
 *    │              ├─ globallyAllowed / noRuleApplies → respond (H ticks)
 *    │              └─ ancestryRequired → slowQueue: BoundedQueue (capacity SQ_Cap)
 *    │                   full? → drop: respond(allow)
 *    │                   ok?   → signal slowSignal
 *    │                   └─ slowDispatchLoop (wakes on slowSignal)
 *    │                        └─ slowWorkerSemaphore.wait() [W permits]
 *    │                             └─ slowWorkerQueue (concurrent)
 *    │                                  └─ waitForProcess + evaluate (T ticks)
 *    │
 *    └─ ESJailAdapter callback (esJailAdapterQueue, serial)
 *         ├─ unjailed → respond(allow) immediately
 *         └─ jailed → check allowlist → checkJailPath → respond (J ticks)
 *
 * Parameters
 * ----------
 *  NumEvents  -- AUTH events delivered to BOTH ES clients
 *  EB_Cap     -- eventBuffer BoundedQueue capacity
 *  SQ_Cap     -- slowQueue BoundedQueue capacity
 *  Workers    -- slowWorkerSemaphore initial value (W)
 *  Deadline   -- ticks until ES kills the client per event (D)
 *  SlowTicks  -- ticks a slow-path worker holds a permit (T)
 *  HotTicks   -- ticks the serial hot path takes per event (H)
 *  JailTicks  -- ticks a jailed event takes on the jail serial queue (J)
 *
 * What TLC checks
 * ---------------
 *  Invariant "NoDeadlineMiss":
 *    Every event on BOTH paths is either responded to within its deadline,
 *    dropped (auto-allowed within the same tick), or still has time remaining.
 *)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS NumEvents,     \* Total AUTH events (delivered to BOTH ES clients)
          EB_Cap,        \* eventBuffer capacity
          SQ_Cap,        \* slowQueue capacity
          Workers,       \* Slow-path semaphore permits (W)
          Deadline,      \* Ticks until ES kills client per event (D)
          SlowTicks,     \* Ticks a slow-path worker occupies a permit (T)
          HotTicks,      \* Ticks the serial hot path consumer takes per event (H)
          JailTicks      \* Ticks a jailed event takes on the jail serial queue (J)

ASSUME NumEvents \in Nat /\ NumEvents >= 1
ASSUME EB_Cap    \in Nat /\ EB_Cap    >= 1
ASSUME SQ_Cap    \in Nat /\ SQ_Cap    >= 1
ASSUME Workers   \in Nat /\ Workers   >= 1
ASSUME Deadline  \in Nat /\ Deadline  >= 2
ASSUME SlowTicks \in Nat /\ SlowTicks >= 1
ASSUME HotTicks  \in Nat /\ HotTicks  >= 1
ASSUME JailTicks \in Nat /\ JailTicks >= 1

Events == 1..NumEvents

NONE == -1

(* ═══════════════════════════════════════════════════════════════════════════
   State variables
   ═══════════════════════════════════════════════════════════════════════════

   FAA adapter path (ESInboundAdapter → FileAuthPipeline):
     faaKind        -- non-deterministic: "hot" or "slow" per event
     faaRespondedAt -- tick the FAA path responded (NONE = pending)
     faaDropped     -- TRUE if dropped by a BoundedQueue (auto-allowed)
     eventBuffer    -- FIFO (protected by OSAllocatedUnfairLock<BoundedQueue.State>)
     slowQueue      -- FIFO (protected by OSAllocatedUnfairLock<BoundedQueue.State>)
     hotBusyUntil   -- tick the serial hotPathQueue consumer becomes free
     workerBusyUntil-- per-worker tick it becomes free (models slowWorkerSemaphore)
     faaSubmitted   -- events submitted to FAA path (models esAdapterQueue serial dispatch)

   Jail adapter path (ESJailAdapter):
     jailKind         -- non-deterministic: "jailed" or "unjailed" per event
     jailRespondedAt  -- tick the jail path responded (NONE = pending)
     jailQueue        -- FIFO (GCD serial queue — unbounded, no drop)
     jailBusyUntil    -- tick the serial esJailAdapterQueue becomes free
     jailSubmitted    -- events submitted to jail path

   Global:
     tick             -- discrete clock
*)
VARIABLE faaKind,
         faaRespondedAt,
         faaDropped,
         eventBuffer,
         slowQueue,
         hotBusyUntil,
         workerBusyUntil,
         faaSubmitted,
         jailKind,
         jailRespondedAt,
         jailQueue,
         jailBusyUntil,
         jailSubmitted,
         tick

vars == <<faaKind, faaRespondedAt, faaDropped, eventBuffer, slowQueue,
          hotBusyUntil, workerBusyUntil, faaSubmitted,
          jailKind, jailRespondedAt, jailQueue, jailBusyUntil, jailSubmitted,
          tick>>

\* ---- Helpers ----

FreeWorkers == { w \in 1..Workers : workerBusyUntil[w] <= tick }

FAADone == \A e \in Events : faaRespondedAt[e] /= NONE \/ faaDropped[e]
JailDone == \A e \in Events : jailRespondedAt[e] /= NONE
AllDone == FAADone /\ JailDone

\* ---- Initial state ----
(* All events arrive at tick 0 (worst-case burst).
   Each event is non-deterministically classified on each path. *)

Init ==
    /\ faaKind        \in [Events -> {"hot", "slow"}]
    /\ faaRespondedAt = [e \in Events |-> NONE]
    /\ faaDropped     = [e \in Events |-> FALSE]
    /\ eventBuffer    = <<>>
    /\ slowQueue      = <<>>
    /\ hotBusyUntil   = 0
    /\ workerBusyUntil = [w \in 1..Workers |-> 0]
    /\ faaSubmitted   = 0
    /\ jailKind       \in [Events -> {"jailed", "unjailed"}]
    /\ jailRespondedAt = [e \in Events |-> NONE]
    /\ jailQueue      = <<>>
    /\ jailBusyUntil  = 0
    /\ jailSubmitted  = 0
    /\ tick           = 0

\* ════════════════════════════════════════════════════════════════════════════
\* FAA adapter path actions
\* ════════════════════════════════════════════════════════════════════════════

(* FAASubmit: an AUTH event arrives via the ES callback and is dispatched to
   esAdapterQueue (serial), which calls pipeline.submit(). The submit path
   acquires the eventBuffer.storage lock (OSAllocatedUnfairLock) to tryEnqueue.
   If the buffer is full the event is dropped (auto-allowed immediately).
   On success, eventSignal (DispatchSemaphore) is signalled. *)
FAASubmit ==
    /\ faaSubmitted < NumEvents
    /\ LET e == faaSubmitted + 1
       IN \/ /\ Len(eventBuffer) < EB_Cap
             /\ eventBuffer' = Append(eventBuffer, e)
             /\ faaDropped' = faaDropped
          \/ /\ Len(eventBuffer) >= EB_Cap
             /\ faaDropped' = [faaDropped EXCEPT ![e] = TRUE]
             /\ eventBuffer' = eventBuffer
    /\ faaSubmitted' = faaSubmitted + 1
    /\ UNCHANGED <<faaKind, faaRespondedAt, slowQueue, hotBusyUntil,
                    workerBusyUntil,
                    jailKind, jailRespondedAt, jailQueue, jailBusyUntil,
                    jailSubmitted, tick>>

(* HotConsume: the serial hotPathQueue consumer wakes on eventSignal, acquires
   the eventBuffer.storage lock to dequeue, then classifies the event.
   Classification acquires rulesStorage, allowlistStorage, and
   ancestorAllowlistStorage locks to read current policy.
   Hot events: respond immediately (H ticks).
   Slow events: acquire slowQueue.storage lock to tryEnqueue.
     If slowQueue is full: drop (auto-allow).
     If enqueued: signal slowSignal (DispatchSemaphore). *)
HotConsume ==
    /\ Len(eventBuffer) > 0
    /\ hotBusyUntil <= tick
    /\ LET e == Head(eventBuffer)
       IN /\ eventBuffer' = Tail(eventBuffer)
          /\ hotBusyUntil' = tick + HotTicks
          /\ IF faaKind[e] = "hot"
             THEN /\ faaRespondedAt' = [faaRespondedAt EXCEPT ![e] = tick + HotTicks]
                  /\ slowQueue' = slowQueue
                  /\ faaDropped' = faaDropped
             ELSE IF Len(slowQueue) < SQ_Cap
                  THEN /\ slowQueue' = Append(slowQueue, e)
                       /\ faaRespondedAt' = faaRespondedAt
                       /\ faaDropped' = faaDropped
                  ELSE /\ faaDropped' = [faaDropped EXCEPT ![e] = TRUE]
                       /\ slowQueue' = slowQueue
                       /\ faaRespondedAt' = faaRespondedAt
    /\ UNCHANGED <<faaKind, workerBusyUntil, faaSubmitted,
                    jailKind, jailRespondedAt, jailQueue, jailBusyUntil,
                    jailSubmitted, tick>>

(* SlowDispatch: the slow dispatch loop wakes on slowSignal, acquires
   slowWorkerSemaphore (DispatchSemaphore, modelled as a free worker slot),
   then acquires slowQueue.storage lock to dequeue. Dispatches work to
   slowWorkerQueue (concurrent). The worker acquires processTree.storage lock
   for ancestry lookup and rulesStorage/allowlistStorage/ancestorAllowlistStorage
   locks for policy evaluation. Holds the semaphore permit for T ticks. *)
SlowDispatch ==
    /\ Len(slowQueue) > 0
    /\ FreeWorkers /= {}
    /\ LET e == Head(slowQueue)
           w == CHOOSE w \in FreeWorkers : TRUE
       IN /\ slowQueue' = Tail(slowQueue)
          /\ faaRespondedAt' = [faaRespondedAt EXCEPT ![e] = tick + SlowTicks]
          /\ workerBusyUntil' = [workerBusyUntil EXCEPT ![w] = tick + SlowTicks]
    /\ UNCHANGED <<faaKind, faaDropped, eventBuffer, hotBusyUntil, faaSubmitted,
                    jailKind, jailRespondedAt, jailQueue, jailBusyUntil,
                    jailSubmitted, tick>>

\* ════════════════════════════════════════════════════════════════════════════
\* Jail adapter path actions
\* ════════════════════════════════════════════════════════════════════════════

(* JailSubmit: an AUTH event arrives via the jail ES callback. The callback
   retains the message and dispatches to esJailAdapterQueue (serial).
   The GCD serial queue is unbounded — no drop behaviour.
   Inside the callback, jailedProcessesLock (OSAllocatedUnfairLock) is acquired
   to check whether the process is jailed. *)
JailSubmit ==
    /\ jailSubmitted < NumEvents
    /\ LET e == jailSubmitted + 1
       IN jailQueue' = Append(jailQueue, e)
    /\ jailSubmitted' = jailSubmitted + 1
    /\ UNCHANGED <<faaKind, faaRespondedAt, faaDropped, eventBuffer, slowQueue,
                    hotBusyUntil, workerBusyUntil, faaSubmitted,
                    jailKind, jailRespondedAt, jailBusyUntil, tick>>

(* JailConsume: the serial esJailAdapterQueue processes one event.
   Acquires jailedProcessesLock to check jail status.
   Unjailed: respond(allow) immediately with cache decision from
     JailFileAccessEventCacheDecisionProcessor (acquires rulesLock).
   Jailed: acquires allowlistStorage lock (global allowlist check),
     then jailRulesStorage lock (jail rule lookup), evaluates
     checkJailPath, responds, then acquires jailMetricsStorage lock
     to update counters. Total: JailTicks for jailed, 0 for unjailed. *)
JailConsume ==
    /\ Len(jailQueue) > 0
    /\ jailBusyUntil <= tick
    /\ LET e == Head(jailQueue)
           duration == IF jailKind[e] = "jailed" THEN JailTicks ELSE 0
       IN /\ jailQueue' = Tail(jailQueue)
          /\ jailRespondedAt' = [jailRespondedAt EXCEPT ![e] = tick + duration]
          /\ jailBusyUntil' = tick + duration
    /\ UNCHANGED <<faaKind, faaRespondedAt, faaDropped, eventBuffer, slowQueue,
                    hotBusyUntil, workerBusyUntil, faaSubmitted,
                    jailKind, jailSubmitted, tick>>

\* ════════════════════════════════════════════════════════════════════════════
\* Clock and termination
\* ════════════════════════════════════════════════════════════════════════════

(* Tick: advance clock when no action can make progress and work remains. *)
Tick ==
    /\ ~AllDone
    /\ faaSubmitted >= NumEvents
    /\ jailSubmitted >= NumEvents
    /\ \/ Len(eventBuffer) = 0
       \/ hotBusyUntil > tick
    /\ \/ Len(slowQueue) = 0
       \/ FreeWorkers = {}
    /\ \/ Len(jailQueue) = 0
       \/ jailBusyUntil > tick
    /\ tick' = tick + 1
    /\ UNCHANGED <<faaKind, faaRespondedAt, faaDropped, eventBuffer, slowQueue,
                    hotBusyUntil, workerBusyUntil, faaSubmitted,
                    jailKind, jailRespondedAt, jailQueue, jailBusyUntil,
                    jailSubmitted>>

(* Stutter once all events are handled — prevents false deadlock. *)
Done ==
    /\ AllDone
    /\ UNCHANGED vars

\* ---- Specification ----

Next == FAASubmit \/ HotConsume \/ SlowDispatch
     \/ JailSubmit \/ JailConsume
     \/ Tick \/ Done

Spec == Init /\ [][Next]_vars
     /\ WF_vars(FAASubmit) /\ WF_vars(HotConsume) /\ WF_vars(SlowDispatch)
     /\ WF_vars(JailSubmit) /\ WF_vars(JailConsume) /\ WF_vars(Tick)

\* ---- Safety invariants ----

(* Core property: no event may be past its deadline without a response
   on EITHER path. All events arrive at tick 0, so the absolute deadline
   is just Deadline.

   FAA path: three sub-conditions per event:
     1. Dropped → safe (auto-allowed in the same tick).
     2. Responded → respondedAt ≤ Deadline.
     3. Neither → tick ≤ Deadline (event still has time).

   Jail path: two sub-conditions per event:
     1. Responded → respondedAt ≤ Deadline.
     2. Not responded → tick ≤ Deadline (event still has time). *)
NoDeadlineMiss ==
    /\ \A e \in Events :
        \/ faaDropped[e]
        \/ faaRespondedAt[e] /= NONE /\ faaRespondedAt[e] <= Deadline
        \/ faaRespondedAt[e] = NONE  /\ ~faaDropped[e] /\ tick <= Deadline
    /\ \A e \in Events :
        \/ jailRespondedAt[e] /= NONE /\ jailRespondedAt[e] <= Deadline
        \/ jailRespondedAt[e] = NONE  /\ tick <= Deadline

\* ---- Capacity analysis ----
(*
 * FAA path:
 *   Hot path throughput: 1 event per H ticks (serial).
 *   Slow path throughput: W × ⌊D/T⌋ events per deadline window.
 *   Bounded queues shed excess: eventBuffer drops beyond EB_Cap,
 *   slowQueue drops beyond SQ_Cap. Drops are safe (auto-allowed).
 *
 *   Deadline miss occurs when a slow event waits too long in the pipeline:
 *     hot_path_delay + slow_queue_wait + T > D
 *
 * Jail path:
 *   Serial processing: 1 event per JailTicks (jailed) or immediate (unjailed).
 *   Unbounded queue: no drop behaviour.
 *   Deadline miss occurs when cumulative serial processing exceeds D:
 *     sum of durations for events ahead in queue + own duration > D
 *
 *   Worst case (all jailed): event k responds at k × J.
 *   Miss when k × J > D, i.e. k > D/J.
 *   With J=1 and D=6: safe up to 6 jailed events.
 *   The jail path lacks the bounded-queue safety valve of the FAA path.
 *)

=============================================================================
