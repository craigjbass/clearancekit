---
id: ADR-S01
domain: security
date: 2026-03-15
status: Accepted
---
# ADR-S01: EC-P256 Policy Signing

## Context

The policy database is stored on disk and is readable by root. An attacker with root privileges could tamper with rules to whitelist malicious processes — bypassing file-access enforcement without touching the GUI or XPC layer. Filesystem permissions alone cannot prevent this because root can override them.

## Options

1. **No signing** — rely on filesystem permissions only. Does not protect against root-level tampering.
2. **HMAC with symmetric key stored alongside the database** — key access equals tamper access; an attacker who can read the database can also forge signatures.
3. **EC-P256 asymmetric signing, private key in keychain with ACL restricted to opfilter** — signing key is inaccessible to any process that does not match opfilter's signing identity, even other root processes.

## Decision

EC-P256 (ECDSA-SHA256) signing via `PolicySigner`. The private key is stored in the System Keychain (`/Library/Keychains/System.keychain`) with a `SecAccess` ACL entry listing only opfilter as a trusted application. `PolicySigner` signs after every write; `Database` verifies on open via `checkSignature`, which resolves one of three states:

- **`.uninitialized`** — no signature row exists and the table is empty. This is genuine trust-on-first-use: opfilter signs the (empty) content immediately and returns `.ok`. The data is trusted because there is nothing to tamper with.
- **`.suspect`** — no signature row exists but the table has rows. This indicates the signature row was deleted while data remained. The data is not loaded silently; the caller receives `.suspect` and triggers a Touch ID re-authorisation flow. An attacker who deletes only the signature row does not get their data loaded.
- **`.verified`** — a signature row exists and `PolicySigner.verify` succeeds. Data is trusted.

A signature row that is present but fails verification also resolves to `.suspect` and discards the policy content.

Secure Enclave was attempted but is architecturally inaccessible from a LaunchDaemon. The SE is accessed via `com.apple.ctkd.token-client`, a per-user LaunchAgent — daemons run in the system context and cannot reach it (see commit `fb6a539` for the documented rationale). This is not an entitlement issue; it is a structural limitation of the macOS daemon environment.

The data-protection keychain (`kSecUseDataProtectionKeychain`) was also evaluated and rejected: it is per-user and unsuitable for a root LaunchDaemon. The deprecated `SecKeychain*` family is therefore used intentionally, as it remains the only API that accepts an explicit System Keychain path in this context.

Key ACL migrated from the old permissive format on first load (commit `4b89e18`): the old key is deleted and a new one created with the correct ACL, preserving no key material from the permissive version.

Initial implementation introduced in `4bb6687`. ACL tightened and migration added across `0216b95`, `67146dd`, `6cdf14c`, and `4b89e18`.

## Consequences

- Tampered or missing signature triggers a Touch ID re-authorisation prompt in the GUI (the signature issue flow introduced in `ca54899`).
- The signing key is inaccessible to any process that does not match opfilter's code signing identity, even other processes running as root or the same user.
- The deprecated `SecKeychain*` APIs are used intentionally; the deprecation warning is accepted as known noise with no viable modern replacement for explicit keychain paths in the daemon context.
- ACL migration runs once at daemon startup, gated by a marker file at `/Library/Application Support/clearancekit/.key-acl-v2`. Subsequent startups are a no-op.
- Software-backed EC-P256 does not provide hardware key binding (unlike Secure Enclave); a root attacker who can modify opfilter's executable could extract the key. The ACL only prevents access by other processes, not offline extraction by a privileged attacker.
