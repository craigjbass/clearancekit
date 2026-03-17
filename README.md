# ClearanceKit

ClearanceKit enforces per-process file access policies on macOS using the Endpoint Security framework. Deny events are surfaced in a native SwiftUI interface, letting you build and refine rules interactively without writing configuration files.

It also supports process ancestry checks within policies, which allows rules that permit typical "living off the land" sub-processes. Note that ancestry checks are more resource-intensive, so it is recommended to scope paths as tightly as possible.

![clearancekit in action](Screenshots/recording.gif)

![App protections](Screenshots/app-protections.png)

## Threat model

[![DEFCON talk on macOS Endpoint Security](https://img.youtube.com/vi/AgYGwZjcsLo/maxresdefault.jpg)](https://www.youtube.com/watch?v=AgYGwZjcsLo)

Modern macOS developer workstations are high-value targets. Unlike iOS, macOS permits unsigned or ad-hoc-signed Mach-O binaries to run outside the App Sandbox, with direct access to the file system and user data. The attack surface is widest around developer tooling — package managers, build systems, language runtimes, and their plugins all execute arbitrary native code with your full user-level permissions the moment you run `npm install`, `pip install`, `brew install`, `cargo build`, or pull a new dependency.

**The supply chain attack surface is enormous.** A malicious package — or a legitimate package with a compromised release — can drop a native dylib or shell script that gets loaded into every subsequent process in your terminal session. Because macOS does not restrict which files an unsandboxed process can read, that one `postinstall` script has the same access to your data as you do.

What can it reach?

- **Apple Notes** — unlocked notes are stored in a readable CoreData SQLite database at `~/Library/Group Containers/group.com.apple.notes/`; individually locked notes are encrypted
- **Signal Desktop** — attachments at `~/Library/Application Support/Signal/attachments.noindex/` are directly readable; the message database is SQLCipher-encrypted with an ACL-restricted keychain entry, but blocking directory access prevents bulk exfiltration of media and documents
- **iMessage** — chat history and attachments are stored under `~/Library/Messages/`
- **Safari cookies** — `~/Library/Cookies/Cookies.binarycookies` is directly readable by any same-user process
- **Firefox and Chrome session cookies** — Firefox stores cookies in plaintext SQLite; Chrome's cookie database is readable on disk
- **SSH private keys** — unprotected `~/.ssh/id_*` files are immediately usable for lateral movement to servers and cloud environments
- **AWS, GCP, and Azure credentials** — plaintext credential and token files at `~/.aws/credentials`, `~/.config/gcloud/`, and `~/.azure/`
- **Git credentials and `.netrc`** — plaintext `~/.git-credentials` and `.netrc` give silent access to every private repository your account can reach
- **GPG private keys** — `~/.gnupg/private-keys-v1.d/` files can be copied for offline passphrase cracking
- **Slack, Discord, and other Electron apps** — conversation history and credentials are stored in LevelDB and SQLite under `~/Library/Application Support/`; whether specific values are encrypted depends on the app
- **Zoom and meeting recordings** — local recordings stored unprotected at `~/Documents/Zoom/`
- **VS Code and JetBrains IDE state** — recent file lists, workspace settings, and extension local storage that map your entire codebase

clearancekit places the Endpoint Security framework between every file-open event and the process that triggered it. When a process you did not explicitly allow attempts to read a protected path — your `~/.ssh` directory, your Notes database, your browser profile — clearancekit intercepts the access, denies it, and surfaces it in the UI so you can decide whether to add a policy or investigate further.

## Installation

Download the latest DMG from the [Releases](../../releases) page, open it, and drag clearancekit to Applications.

On first launch you will be prompted to activate the system extension and grant Full Disk Access — both are required for Endpoint Security to function.

## Architecture

Two components work together:

- **clearancekit.app** — SwiftUI menu bar app. Manages policies, displays live events, and communicates with the system extension over XPC.
- **uk.craigbass.clearancekit.opfilter** — System extension (Endpoint Security). Intercepts `ES_EVENT_TYPE_AUTH_OPEN` events, evaluates policies, and serves the GUI over XPC.

## Development

### Prerequisites

- Xcode 26+
- Apple Developer account with the **Endpoint Security** entitlement approved for your team ID
- Developer ID provisioning profiles for both `uk.craigbass.clearancekit` and `uk.craigbass.clearancekit.opfilter`

### First run

1. Build and run the app (Cmd+R)
2. Open the **Setup** tab and click **Activate Extension** — macOS prompts for approval in System Settings (once only)
3. Grant Full Disk Access to the system extension when prompted

### Attaching the debugger

Use **Debug → Attach to Process by PID or Name** and enter `uk.craigbass.clearancekit.opfilter`. Note that attaching to an ES client can cause watchdog timeouts; `ES_OSLOG_LEVEL=debug` logging is a lower-overhead alternative.

## Troubleshooting

Check system extension state:

```
systemextensionsctl list
```

View extension logs:

```
log stream --predicate 'subsystem == "uk.craigbass.clearancekit.opfilter"' --level debug
```
