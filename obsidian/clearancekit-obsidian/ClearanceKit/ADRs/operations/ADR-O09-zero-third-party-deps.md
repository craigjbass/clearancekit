---
id: ADR-O09
domain: operations
date: 2026-03-22
status: Accepted
---
# ADR-O09: Zero Third-Party Swift Dependencies

## Context

Third-party Swift package dependencies introduce supply-chain risk: each dependency is a potential vector for a compromised package (analogous to npm-style attacks), requires ongoing maintenance (version pinning, security patch tracking), and may introduce licence incompatibilities in a tool distributed to end users. ClearanceKit handles sensitive security decisions at the OS level, making its supply-chain integrity especially important to users who evaluate it before deployment.

## Options

1. **Use SwiftPM packages freely as needed** — lowest initial implementation effort for common tasks; maximum supply-chain exposure; ongoing dependency audit and update burden.
2. **Vet and allowlist selected packages with security review** — reduces scope of exposure; adds a per-package security review process; still requires ongoing maintenance as packages release updates.
3. **Zero third-party Swift dependencies — implement all functionality using Apple frameworks** — no SwiftPM dependency graph; no package registry attack surface; all code is first-party or OS-provided.

## Decision

A strict zero third-party Swift dependencies policy is adopted. All functionality is implemented using Apple-provided frameworks:

- `EndpointSecurity` — kernel event interception
- `Security` — code signing and certificate evaluation
- `AppKit` / `SwiftUI` — GUI
- `SQLite3` (system-provided) — persistence, with a custom Swift adapter written from scratch
- `Foundation` / `Combine` — data types, IPC, and reactive plumbing
- `SystemExtensions` — system extension lifecycle

The Xcode project contains no `Package.swift` and no SwiftPM integration. There is no dependency graph to audit, no lock file to maintain, and no package registry to monitor. This policy is highlighted as a differentiating feature in the README and GitHub Pages site.

## Consequences

- Zero supply-chain attack surface from Swift package registries.
- No SwiftPM dependency graph to audit or update. Scorecard's Vulnerabilities and Binary-Artifacts checks score 10/10 in part because there are no third-party binaries or dependency vulnerabilities to report.
- Some capabilities require more implementation effort than using a library (the SQLite adapter, for example, is written from scratch against the system-provided C API).
- The policy is a hard constraint: contributors proposing a new capability must implement it using Apple frameworks or custom code, with no recourse to a package dependency as a shortcut.
- The zero-dependency property is surfaced in user-facing documentation as a trust signal for security-conscious adopters.
