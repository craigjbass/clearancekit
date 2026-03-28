# FilterInteractor SRP Refactoring Plan

## Problem

`FilterInteractor` violates the Single Responsibility Principle by handling two distinct
code paths — FAA (file-access authorisation via `FileAuthPipeline`) and Jail (synchronous
`handleJailEventSync`) — plus shared output and allowlist state.

## Risk register

| Risk | Mitigation |
|------|-----------|
| Allowlist state diverges between the two interactors | Shared `AllowlistState` reference type; single call-site in `XPCServer.applyAllowlistToFilter` |
| `onEvent` / post-respond side-effects silently broken | `PostRespondHandler` extracted with full body; jail path calls it directly; FAA path calls it via pipeline closure |
| Jail metrics lost after split | `JailFilterInteractor.jailMetrics()` mirrors the current signature; `main.swift` updated to call it on the new type |
| `WeakBox` cycle broken | `FAAFilterInteractor` owns `pipeline`; only `rulesProvider` needs a weak-ref closure; `postRespond` and `allowlistProvider` closures hold non-owning references to `PostRespondHandler` / `AllowlistState` |

## Steps

- [x] **Step 1 — Extract `PostRespondHandler`**
  Create `opfilter/Filter/PostRespondHandler.swift`.
  Move `postRespondQueue`, `auditLogger`, `ttyNotifier`, and `onEvent` into it.
  `FilterInteractor.postRespond` becomes a thin wrapper; `onEvent` becomes a computed property.
  No change to `main.swift` or tests.

- [x] **Step 2 — Extract `AllowlistState`**
  Create `opfilter/Filter/AllowlistState.swift`.
  Move `allowlistStorage` / `ancestorAllowlistStorage` into it.
  `FilterInteractor` holds one `AllowlistState`; all allowlist reads/writes delegate to it.
  No change to `main.swift` or tests.

- [x] **Step 3 — Create `JailFilterInteractor`**
  Create `opfilter/Filter/JailFilterInteractor.swift`.
  Owns `jailRulesStorage`, `jailMetricsStorage`, and the `handleJailEventSync` logic.
  Takes `AllowlistState` and `PostRespondHandler` in its `init`.
  Write focused tests in `Tests/JailFilterInteractorTests.swift`; all existing tests remain green.

- [x] **Step 4 — Create `FAAFilterInteractor`**
  Create `opfilter/Filter/FAAFilterInteractor.swift`.
  Owns `rulesStorage`, `pipeline`, process-tree lifecycle methods, and allowlist update forwarding.
  Takes `AllowlistState` and `PostRespondHandler` in its `init`.
  Write focused tests in `Tests/FAAFilterInteractorTests.swift`; all existing tests remain green.

- [x] **Step 5 — Wire up and delete `FilterInteractor`**
  Update `main.swift`: create `PostRespondHandler`, `AllowlistState`, `FAAFilterInteractor`, `JailFilterInteractor`.
  Wire `onEvent` on `postRespondHandler`.
  Update `ESInboundAdapter` to take `FAAFilterInteractor`.
  Update `ESJailAdapter` to take `JailFilterInteractor`.
  Update `XPCServer` to take `FAAFilterInteractor` + `JailFilterInteractor`.
  Delete `FilterInteractor.swift`.

- [x] **Step 6 — Split the tests**
  Delete `Tests/FilterInteractorTests.swift`.
  Confirm `FAAFilterInteractorTests` and `JailFilterInteractorTests` cover all cases.
