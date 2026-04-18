---
id: ADR-S06
domain: security
date: 2026-03-19
status: Accepted
---
# ADR-S06: opfilter Self-Protection Rule

## Context

opfilter's binary and data files on disk could be modified or replaced by a process with sufficient privileges. Replacing the binary between restarts would allow a compromised version to run at next launch without any indication to the user. This attack surface exists even when SIP is active for system paths — opfilter's data directory is user-writable by design (it stores user policy) and the binary resides in a location accessible to the installer.

## Options

1. **No self-protection** — rely on macOS SIP for system paths. Does not protect the data directory or installation paths outside SIP scope.
2. **Integrity check on startup only** — verifies files have not changed since last run by comparing hashes. Detects tampering after the fact but does not prevent it.
3. **FAA self-protection rule** — opfilter adds policy entries protecting its own binary path and data directory. Any write attempt by a process other than opfilter triggers an ES AUTH deny before the write reaches the filesystem.

## Decision

opfilter adds FAA rules protecting its own binary path and database path at startup (`e71379d`). The rules permit only processes matching opfilter's exact signing ID; all other processes are denied write access by the ES framework.

The protection was initially keyed to team ID only, which would have allowed any process signed by the same team to bypass it. `8386ae0` tightened this from team-ID-only to the exact opfilter signing ID (`XPCConstants.serviceName`), so only opfilter itself satisfies the rule.

## Consequences

- Any attempt by another process to write to opfilter's binary or database paths is denied at the ES kernel layer, before the write reaches the filesystem. This protection is only active while opfilter is running — if opfilter is not running, the FAA rule is not in effect and binary replacement is not blocked by this mechanism.
- opfilter can still write its own database because it holds the exact signing ID that the rule permits.
- The self-referential enforcement loop — opfilter enforces rules that protect itself — is intentional and resolved by the startup sequence: the database is loaded before the ES client becomes active. Once enforcement begins, the self-protection rule is in effect.
- The tightening from team ID to exact signing ID (bundle ID) means other tools in the same developer account cannot access opfilter's data paths, reducing the blast radius of a compromised companion tool.
- Binary replacement between restarts is blocked for any process other than opfilter **while opfilter is active**. If opfilter is not running, the FAA rule is not in effect and this protection does not apply. An attacker with a debugger attached to opfilter (blocked by removing `get-task-allow` — see ADR-S03) or with direct kernel access (blocked by SIP) remains out of scope.
