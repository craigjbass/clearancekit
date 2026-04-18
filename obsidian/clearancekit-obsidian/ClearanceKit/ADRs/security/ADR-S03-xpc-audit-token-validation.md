---
id: ADR-S03
domain: security
date: 2026-03-13
status: Accepted
---
# ADR-S03: XPC Audit Token Validation

## Context

NSXPCConnection exposes a `processIdentifier` (PID) property that appears to identify the connecting process. PID-based checks are vulnerable to PID reuse attacks: an attacker process can race to occupy a trusted PID in the window between the legitimate process exiting and the check executing. This is a known macOS security weakness documented by Apple and by external security researchers.

opfilter exposes an XPC service that accepts policy queries and mutations from the GUI. If the XPC boundary is not properly validated, a malicious process could impersonate the GUI and issue policy-mutating RPC calls directly.

## Options

1. **PID check via `connection.processIdentifier`** — vulnerable to PID reuse; rejected.
2. **Code signing entitlement check** — requires adding a specific entitlement to the GUI binary; validates the client claims a known identity, but does not use a kernel-stable handle.
3. **Audit token verification** — read `connection.auditToken`, verify code signing identity via `SecCode` API using the audit token as a kernel-assigned, unforgeable handle. Audit tokens encode PID version alongside PID, eliminating the reuse window.

## Decision

`ConnectionValidator` reads the `auditToken` from each incoming `NSXPCConnection` and verifies the connecting process via `SecCodeCopyGuestWithAttributes` using `kSecGuestAttributeAudit`. Three checks are applied to every connection:

1. **Apple-anchored signature with expected team ID** — validated via a `SecRequirement` string:
   ```
   anchor apple generic and certificate leaf[subject.OU] = "37KMK6XFTT"
   ```
   The `anchor apple generic` clause enforces that the certificate chain is rooted in Apple's CA. Without it, any certificate with the matching `subject.OU` value — regardless of issuer — would satisfy the requirement. The `certificate leaf[subject.OU]` clause then narrows the match to the specific team identifier within that Apple-anchored chain.
2. **Bundle identifier prefix** — must match `XPCConstants.bundleIDPrefix`.
3. **Forbidden entitlements** — connections are rejected if the client carries `com.apple.security.cs.allow-dyld-environment-variables`, `com.apple.security.cs.disable-library-validation`, or `com.apple.security.get-task-allow`. The entitlement check is skipped in DEBUG builds.

`get-task-allow` was removed from the GUI's entitlements file in `0a997cd` to close the debugger-attach vector — a process that can be debugged can have its memory read and written by an attached debugger, weakening the code signing guarantee.

The `auditToken` property is public on macOS 14+ but is not bridged to Swift's Foundation overlay. An Objective-C runtime shim (`NSXPCConnection+AuditToken.swift`) provides access. Protocol version bumped to `2.0` to mark this hardening boundary.

Introduced in `7b23e09`; wired into the XPC listener and GUI entitlement removal in `0a997cd`.

## Consequences

- Only the exact signed GUI binary (matching team ID and bundle ID prefix, with an Apple-rooted certificate chain) can send XPC messages. Any other process — including one running as the same user — is rejected at the connection level.
- Audit tokens are issued by the kernel and cannot be forged by user-space code, eliminating the PID reuse attack surface.
- The connection-level check fires on every new connection, not per-message. This is appropriate because the audit token is stable for the lifetime of a connection.
- Removing `get-task-allow` from the GUI means attaching a debugger to the shipped GUI binary is not possible without bypassing SIP, consistent with a production security posture.
- The Objective-C shim is a known workaround for a Swift overlay gap; if Apple bridges `auditToken` to Swift Foundation in a future release, the shim can be removed.
