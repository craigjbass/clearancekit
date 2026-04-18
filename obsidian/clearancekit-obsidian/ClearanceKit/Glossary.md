# Glossary

Domain and infrastructure terms used throughout the ClearanceKit codebase and its ADRs.

| Term | Definition |
|------|------------|
| FAA | File Access Authorization — macOS Endpoint Security mechanism for intercepting and allowing/denying file operations. |
| ES | Endpoint Security — Apple kernel framework for system security monitoring and enforcement. |
| AUTH event | Endpoint Security event requiring a synchronous allow/deny response before the deadline. |
| NOTIFY event | Endpoint Security event delivered post-facto for logging/monitoring; no response required. |
| opfilter | The ClearanceKit System Extension process that holds the ES client and enforces policy. |
| clearancekit | The ClearanceKit GUI app (menu bar) that allows users to manage policy rules. |
| XPC | Cross-Process Communication — macOS IPC mechanism used between clearancekit and opfilter. |
| audit token | Kernel-provided unforgeable process identity token; safer than PID for authentication. |
| ProcessSignature | Pair of (teamID, signingID) used to identify a code-signed process in policy rules. |
| FAARule | A policy rule specifying which ProcessSignature can access which path pattern. |
| AppPreset | A named bundle of FAARule entries for a specific macOS application. |
| Global allowlist | A list of ProcessSignature entries that bypass all FAA policy evaluation. |
| Managed policy tier | Rules deployed via MDM (macOS preference key); sit between baseline and user rules. |
| Baseline | Built-in Apple system process allowances that cannot be removed by users. |
| Policy signing | EC-P256 ECDSA signature over the serialised policy database to detect tampering. See [[ADRs/security/ADR-S01-ec-p256-policy-signing]]. |
| SLSA L3 | Supply-chain Levels for Software Artifacts Level 3 — provenance attestation for release builds. |
| Sigstore | A transparency log and signing framework for verifying software build provenance. |
| OpenSSF Scorecard | Open Source Security Foundation automated supply chain security scoring tool. |
| Jail | ClearanceKit feature that confines a process to an explicit set of allowed path patterns. |
| AccessKind | Enum (read/write) derived from ES open flags; used for write-only rule evaluation. |
| Preset drift | Condition where an installed preset's rule set differs from the current built-in version. |
| pidVersion | Kernel-assigned version counter per PID, reset on reuse; part of ProcessIdentity. |
| Santa | Google's macOS binary allowlisting tool; ClearanceKit can export policy in Santa format. |
| mobileconfig | Apple MDM configuration profile format; ClearanceKit can export rules as mobileconfig. |

See also [[Architecture Overview]] and the component notes under [[Components/opfilter]].
