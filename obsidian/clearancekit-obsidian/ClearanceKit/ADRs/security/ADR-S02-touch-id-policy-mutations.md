---
id: ADR-S02
domain: security
date: 2026-03-13
status: Accepted
---
# ADR-S02: Touch ID for Policy Mutations

## Context

Policy rules control which processes can access which files. A compromised GUI — for example via a malicious app spoofing the GUI process, or a logic bug in the UI layer — could silently add allowlist rules without the user's knowledge. The XPC validation (ADR-S03) ensures only the legitimate signed GUI binary can connect, but it does not prevent an attacker who has already compromised the GUI from issuing mutations through the XPC interface.

## Options

1. **No auth gate** — any GUI interaction can mutate policy. No user-presence signal.
2. **Password confirmation dialog** — via a custom UI prompt. Subject to UI spoofing; does not use the OS biometric stack.
3. **Touch ID / biometric via `LAContext`** — integrates with the macOS biometric subsystem. Falls back to password when Touch ID hardware is unavailable.

## Decision

All policy mutations (add, edit, delete rules; export; import; signature repair) require a successful `LAContext.evaluatePolicy(.deviceOwnerAuthentication, ...)` call before any state is mutated or sent to opfilter over XPC.

`.deviceOwnerAuthentication` is used (not `.deviceOwnerAuthenticationWithBiometrics`). The initial implementation in `e43a3a2` used the biometrics-only policy; `a978f96` corrected this to the fallback-capable policy so that the application remains usable on Macs without Touch ID hardware and on accounts where Touch ID is not enrolled.

Error display for auth failure was added in `a978f96`. Policy export and import with Touch ID protection added in `e713646`. The Touch ID gate for signature repair was introduced as part of the signature issue resolution flow in `ca54899`.

## Consequences

- User presence is required for all policy changes. A compromised GUI process cannot mutate policy without the user physically authenticating.
- MDM-deployed managed profile rules bypass Touch ID — they arrive via a privileged system channel (not the GUI), so the biometric gate does not apply to them.
- Background or automated policy updates are not possible through the normal GUI path.
- Policy export and import both require Touch ID, consistent with the mutation gate.
- On hardware without Touch ID, the fallback to password provides equivalent user-presence verification.
- Authentication errors surface to the user in the UI rather than silently failing; sheets remain open on auth failure to allow retry.
