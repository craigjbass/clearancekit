---
id: ADR-A02
domain: architecture
date: 2026-02-19
status: Accepted
---
# ADR-A02: Daemon/GUI Separation

## Context

macOS requires a System Extension to hold an Endpoint Security client. A System Extension runs as a privileged, sandboxed process managed by the OS and cannot present a GUI directly. A GUI app cannot hold a System Extension and display a window in the same process.

The original ClearanceKit had GUI code and privileged ES policy code in separate binaries from the start, but the division of responsibilities evolved significantly. A separate `Daemon` process was introduced (commit `fe28ccc`, 2026-02-19) to hold policy storage and XPC brokering between opfilter and the GUI. Policy storage moved from the GUI into the Daemon (commit `e71379d`, 2026-03-13). Process enumeration moved from the GUI (where App Sandbox blocked `proc_listallpids`) into the Daemon (commit `c525c98`, 2026-03-13). The Daemon was then merged back into opfilter (commit `5a88795`, 2026-03-16), making opfilter the single privileged process.

## Options

1. **Single process** — not possible; macOS system constraints prevent an ES client and a GUI from coexisting in one process.
2. **Separate daemon + system extension** — two privileged root processes (daemon for policy/XPC, opfilter for ES). Introduced briefly; added an extra XPC hop on every event and policy mutation, and doubled the attack surface.
3. **System Extension (opfilter) + GUI (clearancekit) connected via XPC** — opfilter is the single privileged process holding the ES client, policy database, and XPC server; the GUI is a sandboxed app communicating exclusively over XPC.

## Decision

opfilter is the single privileged process. It holds the ES client, enforces all file-access policy, stores the signed SQLite database, enumerates running processes, and serves the GUI via `XPCServer`. The GUI (`clearancekit`) is a sandboxed SwiftUI app that communicates exclusively through `NSXPCConnection`.

The intermediate Daemon target was removed in commit `5a88795`. Policy storage, process enumeration, and connection validation that had lived in `Daemon/` were moved directly into opfilter's adapter subdirectories (`opfilter/Database/`, `opfilter/XPC/`, `opfilter/Policy/`).

opfilter protects its own database directory with a FAA rule: only processes signed by team `37KMK6XFTT` may open files there, enforced at the ES kernel layer.

## Consequences

- All policy mutation goes through an XPC round-trip (GUI → opfilter). There is no direct file-system path from the GUI to the policy database.
- Eliminating the Daemon removed one full XPC hop from every event notification and policy update.
- App Sandbox on the GUI is fully enforced; calls that require root (process listing, code-signing lookups) are handled in opfilter and proxied over XPC.
- opfilter's self-protecting FAA rule means a compromised GUI app cannot tamper with stored policy even if it escapes its sandbox.
- The XPC Mach service name is `uk.craigbass.clearancekit.opfilter`; any reconnection from the GUI targets this single endpoint.
