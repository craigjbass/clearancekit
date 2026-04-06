# Security Policy

## Supported Versions

The latest one (as in current build). I might introduce a better release version approach if people find this useful.

## Reporting a Vulnerability

Report vulnerabilities privately via GitHub's private vulnerability reporting:
https://github.com/craigjbass/clearancekit/security/advisories/new

You can also use the "Report a vulnerability" button under the repository's
[Security tab](https://github.com/craigjbass/clearancekit/security). I will liaise from there.

## Security Disclosure Guide

### Hotspots to report

The following areas are considered in-scope security vulnerabilities. Please report these through the GitHub Security tab as described above.

- **Living off the land vulnerabilities in preset global allow list entries** — if a process included in the built-in global allowlist can be abused to exfiltrate data or bypass protections without modification, that is a security issue.
- **XPC service manipulation and Touch ID / auth flow circumvention** — attacks that subvert the XPC communication between the app and the system extension, or that bypass the Touch ID / authorisation prompts to gain elevated access.
- **Policy database manipulation** — techniques that allow a process not code signed by `37KMK6XFTT` to alter stored policies in a way that is not reflected in the GUI or is not authorised by the user.

### Out of scope

The following are not treated as security vulnerabilities. Please report them as enhancements or bugs instead.

- **App preset gaps** — a built-in app protection that does not cover every sensitive path for a given application is a coverage gap, not a security vulnerability.
- **Policy enforcement failures** — a process that is denied by policy but still manages to access a file due to a kernel or OS behaviour outside ClearanceKit's control should be reported as a bug.
