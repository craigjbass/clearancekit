---
id: ADR-F08
domain: features
date: 2026-03-03
status: Accepted
---
# ADR-F08: ES Response Caching

## Context

`ES_EVENT_TYPE_AUTH_OPEN` fires for every file access. Long-lived processes that repeatedly open the same files — editors, IDEs, build tools — would cause policy evaluation to run on every open call. Policy evaluation involves lock acquisition, a path classification lookup, and potentially an ancestry check. Repeated evaluation for the same `(process, path)` pair wastes CPU cycles and increases callback latency.

## Options

1. No caching — evaluate policy on every event; simplest but highest CPU cost on workloads with repeated file accesses.
2. In-process LRU cache — requires custom invalidation logic, adds memory overhead, and duplicates some of the kernel's own vnode tracking.
3. ES kernel-level cache via `cache` flag on `es_respond` — the kernel maintains the cache keyed by `(audit_token, vnode)` and skips future callbacks for cached decisions.

## Decision
Pass `cache: true` to `es_respond` for decisions where the result is stable. The ES kernel caches the result and skips future `AUTH_OPEN` callbacks for the same `(process, path)` pair (keyed by audit token + vnode identity) until `es_clear_cache` is called. The caching rules are:

- **Allow, no ancestry required** — `cache: true`. The outcome is determined solely by policy rules, which only change on explicit update.
- **Deny, no ancestry required** — `cache: true`. `FileAccessEventCacheDecisionProcessor` returns `!ancestorEvaluationRequired`, which is `true` here. Caching denials for non-ancestry rules avoids re-evaluation on every subsequent access and is safe because the kernel cache is cleared on every policy update.
- **Allow or deny, ancestry evaluation required** — `cache: false`. Ancestry state changes on FORK and EXIT; a cached decision could become incorrect if the process tree changes between evaluations.
- **Write-only rule matches** — `cache: false`. Detailed in the write-only hazard below.
- **Globally-allowed events** (matching `GlobalAllowlist`) — always `cache: true` (`2cebd4f`). These are the highest-volume events and the bypass decision never changes per policy update.

`FileAccessEventCacheDecisionProcessor` (in `Shared/`) encapsulates the allow/deny caching logic and is covered by tests. It is not currently wired into any hot path directly; `JailFileAccessEventCacheDecisionProcessor` is the separate type used for the jail adapter's non-jailed fast-path. The main FAA pipeline (`FileAuthPipeline`) makes cache decisions inline at the call to `event.respond`.

`es_clear_cache` is called:
- Once at startup after ES client setup.
- On every policy update delivered via XPC (`applyRulesToFilter`, `applyJailRulesToFilter`) so stale cached decisions do not persist after rule changes.

Write-only rule matches must not be cached. The `bd916e9` commit documents the hazard and adds a regression test: a write-only rule covering a read event must respond with `cache: false`. The `classifyPaths` fast path already routes write-only rule read events to the `.processLevelOnly` branch, which calls `respond(_, false)`, so the cache exclusion is maintained by architecture rather than a runtime flag check on the hot path.

## Consequences

- Dramatic reduction in opfilter CPU on workloads with repeated file accesses by the same process.
- Deny decisions for non-ancestry rules are also cached, halving the evaluation cost for stable deny outcomes.
- Every policy update via XPC triggers `es_clear_cache` — this is a brief stall but ensures correctness. The frequency of policy updates is low in practice.
- Write-only rule cache exclusion is a correctness constraint, not a performance choice. Breaking it would allow writes to silently bypass write-only rules from the same process for the same file until next cache clear.
- The ES kernel cache is per-ES-client, so the FAA client and the jail client maintain independent caches.
