---- MODULE ESAuthDeadline ----
\*
\* Formal model of the opfilter AUTH event handling pipeline.
\*
\* The Endpoint Security framework delivers AUTH messages on a serial
\* callback queue. Each callback dispatches a Task onto Swift's bounded
\* cooperative thread pool and returns immediately. The Task evaluates
\* policy and calls respond(). Every AUTH message carries a mach-time
\* deadline; if no response arrives before it the ES framework SIGKILLs
\* the client process.
\*
\*   Termination Reason: Namespace ENDPOINTSECURITY, Code 2,
\*   EndpointSecurity client terminated because it failed to respond
\*   to a message before its deadline
\*
\* Pipeline (real system)
\* =====================
\*   ES framework  ->  serial callback  ->  Task { }  ->  cooperative pool  ->  respond()
\*   (producer)        (dispatch)           (enqueue)     (bounded threads)     (consumer)
\*
\* The model shows that a startup burst of AUTH events can saturate the
\* cooperative pool, causing tasks at the tail of the FIFO queue to miss
\* their deadlines even though the callback handler returns instantly.
\*
\* Run:  tlc ESAuthDeadline -config ESAuthDeadline.cfg
\*
\* Expected: TLC finds a counterexample to ClientNeverTerminated.
\*           The error trace IS the explanation of the crash.

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    MaxEvents,      \* AUTH events delivered during the startup burst
    PoolSize,       \* Cooperative thread pool capacity (~= CPU core count)
    EvalTime,       \* Ticks a task holds a pool thread (policy eval + post-response work)
    Deadline        \* Ticks from arrival before ES terminates the client

VARIABLES
    clock,          \* Monotonic logical clock
    events,         \* [1..MaxEvents -> record] per-event state
    nextID,         \* Next event ID to deliver (1..MaxEvents+1 when all delivered)
    taskQueue,      \* FIFO sequence of event IDs awaiting a pool thread
    poolInUse,      \* Count of pool threads currently occupied
    alive           \* FALSE once ES terminates the client

vars == <<clock, events, nextID, taskQueue, poolInUse, alive>>

EventIDs == 1..MaxEvents

(* ───────── Initial state ───────── *)

Init ==
    /\ clock     = 0
    /\ events    = [id \in EventIDs |->
                      [state |-> "pending", arrivedAt |-> 0, startedAt |-> 0]]
    /\ nextID    = 1
    /\ taskQueue = <<>>
    /\ poolInUse = 0
    /\ alive     = TRUE

(* ───────── Actions ───────── *)

\* ES delivers the next AUTH event on the serial callback queue.
\* The handler calls interactor.handle(.fileAuth) which executes
\*   Task { await self.handleFileAuth(event) }
\* and returns. The event enters the task queue without occupying a
\* pool thread. Multiple events can be delivered within a single tick
\* because the handler is non-blocking.
Deliver ==
    /\ alive
    /\ nextID <= MaxEvents
    /\ events' = [events EXCEPT
         ![nextID] = [state |-> "queued", arrivedAt |-> clock, startedAt |-> 0]]
    /\ taskQueue' = Append(taskQueue, nextID)
    /\ nextID' = nextID + 1
    /\ UNCHANGED <<clock, poolInUse, alive>>

\* The Swift runtime picks the head-of-queue Task and assigns it a
\* cooperative pool thread. Only possible when a thread is free.
\* Maps to: Swift cooperative thread pool scheduling a Task continuation.
Schedule ==
    /\ alive
    /\ Len(taskQueue) > 0
    /\ poolInUse < PoolSize
    /\ LET id == Head(taskQueue)
       IN events' = [events EXCEPT
            ![id] = [@ EXCEPT !.state = "running", !.startedAt = clock]]
    /\ taskQueue' = Tail(taskQueue)
    /\ poolInUse' = poolInUse + 1
    /\ UNCHANGED <<clock, nextID, alive>>

\* A running Task completes and calls respond(), releasing the thread.
\* EvalTime covers the full thread hold time: policy evaluation,
\* respond() call, and post-response work (logging, XPC broadcast).
\* Maps to: handleFileAuth completing and Task returning.
Complete ==
    /\ alive
    /\ \E id \in EventIDs:
         /\ events[id].state = "running"
         /\ clock >= events[id].startedAt + EvalTime
         /\ events' = [events EXCEPT ![id].state = "responded"]
         /\ poolInUse' = poolInUse - 1
    /\ UNCHANGED <<clock, nextID, taskQueue, alive>>

\* An event's ES deadline expires while it is still queued or running
\* without having responded. The framework terminates the client.
Miss ==
    /\ alive
    /\ \E id \in EventIDs:
         /\ events[id].state \in {"queued", "running"}
         /\ clock >= events[id].arrivedAt + Deadline
         /\ events' = [events EXCEPT ![id].state = "expired"]
         /\ alive' = FALSE
         /\ poolInUse' = IF events[id].state = "running"
                          THEN poolInUse - 1 ELSE poolInUse
    /\ UNCHANGED <<clock, nextID, taskQueue>>

\* Logical time advances by one tick.
\* Guarded: time cannot advance while a task is schedulable (queued task
\* AND free pool thread) or completable (running task past EvalTime).
\* This captures the real-world property that cooperative pool scheduling
\* and task completion are near-instant compared to the deadline timescale.
\* Deadline misses arise from pool SATURATION (all threads occupied by
\* long-running work), not from scheduler or completion latency.
Tick ==
    /\ alive
    /\ ~(Len(taskQueue) > 0 /\ poolInUse < PoolSize)
    /\ ~(\E id \in EventIDs:
           events[id].state = "running" /\ clock >= events[id].startedAt + EvalTime)
    /\ clock' = clock + 1
    /\ UNCHANGED <<events, nextID, taskQueue, poolInUse, alive>>

(* ───────── Specification ───────── *)

Next == Deliver \/ Schedule \/ Complete \/ Miss \/ Tick

Fairness ==
    /\ WF_vars(Tick)
    /\ WF_vars(Deliver)
    /\ WF_vars(Schedule)
    /\ WF_vars(Complete)
    /\ WF_vars(Miss)

Spec == Init /\ [][Next]_vars /\ Fairness

(* ───────── Properties ───────── *)

\* INVARIANT (expected to be VIOLATED).
\* The ES client is never terminated.
\* TLC's counterexample trace is the formal proof of the bug.
ClientNeverTerminated == alive

\* Type invariant (should hold in all reachable states).
TypeOK ==
    /\ clock \in Nat
    /\ nextID \in 1..(MaxEvents + 1)
    /\ poolInUse \in 0..PoolSize
    /\ alive \in BOOLEAN
    /\ \A id \in EventIDs:
         events[id].state \in {"pending", "queued", "running", "responded", "expired"}

\* State-space bound for TLC (not part of the logical specification).
ClockBound == clock <= 10

====
