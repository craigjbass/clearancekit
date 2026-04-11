# ClearanceKit vs SELinux

This document compares ClearanceKit's file-access enforcement model with SELinux, and shows how you would approximate ClearanceKit's jail and policy features using SELinux primitives — and why the approximations involve meaningful trade-offs.

## Background

Both tools implement Mandatory Access Control (MAC): a kernel-enforced layer that constrains what a process may do regardless of the permissions held by the user running it. Beyond that shared starting point they diverge significantly in threat model, policy language, and maintenance burden.

| | ClearanceKit | SELinux |
|---|---|---|
| **Platform** | macOS | Linux |
| **Enforcement point** | Apple Endpoint Security framework | LSM (Linux Security Module) hooks in the kernel |
| **Process identity** | Cryptographic code signing — Team ID + Signing ID | Security context label — `user:role:type:level` |
| **Path matching** | Glob patterns on protected path prefixes | File context labels applied at label time (`restorecon`/`chcon`) |
| **Process confinement** | Jail rules — deny all access outside allowed path prefixes | Domain transitions — restrict a domain's `allow` rules |
| **Policy distribution** | GUI or MDM-managed Apple Configuration Profile | Policy modules (`.te`, `.fc`, `.if` files) compiled with `checkpolicy` |
| **Ancestry tracking** | First-class: `AllowedAncestorSignatures` / `AllowedAncestorProcessPaths` | Not available in the core policy language |
| **Binary integrity** | Cryptographic signature verified by the kernel at `exec` time | Optional, via IMA/EVM or `fs-verity` |
| **Update maintenance** | Zero: signing identity is stable across releases | Manual: file contexts must be relabelled; hash-based policies need re-signing after every update |

---

## Policy model

### ClearanceKit

An `FAAPolicy` rule names a protected path prefix and lists which processes may access it. Processes are identified by their code signing identity in `teamID:signingID` format — a pair derived from the Developer ID certificate embedded in the binary by the developer at build time and verified cryptographically by the macOS kernel at process creation.

```
apple:com.apple.Safari  →  may access  ~/Library/Cookies/
ABCDE12345:com.example.tool  →  may access  /var/log/example/
```

A process that does not appear in any rule for a given protected path is denied access, regardless of which user is running it or where the binary sits on disk.

### SELinux

SELinux implements Type Enforcement (TE): every process runs in a *domain* (e.g. `python_t`), every file is labelled with a *type* (e.g. `user_home_t`), and `allow` rules in the policy grant specific access vectors between them.

```
# Allow processes in python_t to read files labelled user_home_t
allow python_t user_home_t:file { read open getattr };
```

Domain assignment is driven by the path of the executable being launched and any explicit transition rules (`type_transition`, `domain_auto_trans`). There is no cryptographic check on the binary content itself — if `/usr/bin/python3` is replaced by a malicious binary, the replacement inherits the `python_t` domain and all its `allow` rules.

### Key difference: identity is cryptographic, not path-based

ClearanceKit binds policy to the *signature* of the binary, not its path. A trojanised `python` replacement at `/usr/bin/python3` carries a different or absent signing certificate and will be denied by any policy that names the genuine Python Team ID. SELinux cannot make this distinction without additional tooling (see [IMA/EVM below](#sha-signatures-selinux-imaev-and-the-maintenance-problem)).

---

## Process confinement — approximating ClearanceKit jails in SELinux

ClearanceKit's jail feature confines a process to a specific set of path prefixes. Any file access outside those prefixes is denied inline, before the event reaches other policy rules.

```xml
<key>JailedSignature</key>
<string>ABCDE12345:com.example.tool</string>
<key>AllowedPathPrefixes</key>
<array>
    <string>/tmp/**</string>
    <string>/var/log/example/**</string>
</array>
```

### SELinux approximation: a tightly scoped domain

The closest SELinux equivalent is a custom domain that has `allow` rules only for the specific path labels you want to permit, and no `allow` rules for anything else.

**Step 1 — define the domain**

```
# example_tool.te
policy_module(example_tool, 1.0)

type example_tool_t;
type example_tool_exec_t;

domain_type(example_tool_t)
domain_entry_file(example_tool_t, example_tool_exec_t)

# Transition into example_tool_t when the binary is executed
type_transition init_t example_tool_exec_t : process example_tool_t;
```

**Step 2 — label the binary and the allowed paths**

```bash
# Label the executable so the domain transition fires
semanage fcontext -a -t example_tool_exec_t '/usr/bin/example-tool'
restorecon -v /usr/bin/example-tool

# Label the allowed path prefixes
semanage fcontext -a -t example_tool_rw_t '/tmp(/.*)?'
semanage fcontext -a -t example_tool_rw_t '/var/log/example(/.*)?'
restorecon -Rv /tmp /var/log/example
```

**Step 3 — write the allow rules**

```
# Allow read/write within the labelled prefixes only
allow example_tool_t example_tool_rw_t:dir { read write search open getattr };
allow example_tool_t example_tool_rw_t:file { read write create unlink open getattr };

# Allow access to common runtime resources (proc, dev/null, etc.)
# These must be enumerated explicitly — the default is deny all.
allow example_tool_t proc_t:file { read open };
allow example_tool_t devnull_device_t:chr_file { rw_file_perms };
```

**Where the SELinux approximation falls short**

- **Path-based, not signature-based.** The domain transition fires because the binary is at a labelled path. If an attacker replaces the binary at that path, the replacement inherits `example_tool_t`.
- **Label scope is global.** Any process in `example_tool_t` may access any file labelled `example_tool_rw_t` — the policy cannot express "only when the process was spawned by this specific parent".
- **Unlabelled files are not automatically denied.** Files that have never been labelled or have been moved without restoring context carry a default label (often `unlabelled_t`) that may be accessible under a permissive rule elsewhere.
- **Wildcards are policy-time expansions.** ClearanceKit evaluates glob patterns at enforcement time against the actual path string. SELinux wildcard support in `semanage fcontext` uses POSIX extended regular expressions applied at label time — a new file tree that appears after labelling is not automatically covered until `restorecon` is run again.

---

## SHA signatures: SELinux, IMA/EVM, and the maintenance problem

### Linux Integrity Measurement Architecture (IMA) and Extended Verification Module (EVM)

Linux offers two integrity subsystems that address the binary-identity gap in pure SELinux:

- **IMA** measures file hashes and can enforce that only files with a valid signature (RSA over SHA256, stored in an extended attribute) may be executed or read.
- **EVM** protects the security extended attributes themselves from tampering by covering them with an HMAC.

Together they allow a Linux policy of the form: "only execute binaries whose SHA256 hash is listed in the kernel's measurement log and whose IMA signature is valid."

**Example IMA policy rule to require signatures on executable files:**

```
appraise func=BPRM_CHECK appraise_type=imasig
```

With a policy signed by the IMA signing key, only binaries whose `security.ima` extended attribute contains a valid signature will be allowed to execute.

### Why this approach creates a significant maintenance burden

IMA/EVM signatures are bound to the exact bytes of each binary. Every software update — security patch, minor version bump, or recompilation — produces a new binary with a different SHA256 hash. The old IMA signature is immediately invalid.

On a developer workstation where `apt upgrade`, `dnf update`, or a language runtime install runs daily, this means:

1. Every update requires regenerating and re-attaching the IMA signature for each changed binary.
2. Tools that update most frequently — package managers, language runtimes, build tools — are exactly the binaries most likely to be targeted in a supply chain attack, and exactly the ones requiring the most signature maintenance.
3. An unattended update or a CI pipeline that updates dependencies will break any IMA-enforced policy until the signatures are refreshed.

This is not a theoretical concern: it is the same operational cost that makes tools like AIDE and Tripwire difficult to maintain on active machines. Policies go stale, the maintenance is neglected, and the protection lapses precisely when it is most needed.

### How ClearanceKit avoids this

ClearanceKit does not use file hashes. Policies reference a Team ID and Signing ID — the Developer ID certificate and bundle identifier. These are stable across the entire lifetime of a developer's relationship with Apple. When Apple ships a Safari update, the new binary carries the same `apple:com.apple.Safari` identity as the old one. A policy written once remains valid indefinitely.

The only reason to update a policy is a deliberate decision to trust different software, not merely that trusted software was updated.

---

## Process ancestry

ClearanceKit supports ancestry-based rules as a first-class concept:

```xml
<key>AllowedAncestorSignatures</key>
<array>
    <string>ABCDE12345:com.example.ci-runner</string>
</array>
```

This rule allows a child process to access a protected path only if its process tree contains the specified signing identity. The immediate process identity is irrelevant — what matters is who launched it.

This is useful for scenarios such as: "allow `npm install` to run, but only when it was invoked from our trusted CI runner", or "allow a build tool to read source files, but not when launched interactively by a shell."

SELinux has no equivalent mechanism. The `type_transition` rule fires on the *exec* of a specific binary in a specific domain, but there is no way to express "only grant this domain transition if the grandparent process is in a specific domain." Policy decisions are local to the process being evaluated at exec time, not to its ancestry chain.

The `pam_selinux` module and RBAC roles allow different users to obtain different initial domains, and `newrole` / `runcon` can change the context, but neither mechanism allows an ancestor's identity to flow down as a policy constraint on what a descendant may access.

---

## Global allowlist and bypass semantics

ClearanceKit's `GlobalAllowlist` allows specific processes (identified by signing identity or path) to bypass all FAAPolicy rules unconditionally. The `GlobalAncestorAllowlist` variant bypasses rules when any ancestor matches, allowing entire process trees spawned by trusted processes (e.g. an MDM agent or another security tool) to operate without interference.

In SELinux, the closest construct is an *unconfined* domain such as `unconfined_t`, which has broadly permissive rules. However:

- `unconfined_t` is all-or-nothing: a process either gets all permissions or none.
- There is no native concept of "bypass rules if your parent process is in domain X". A child process inherits or transitions into a domain based on its own executable label, not its parent's runtime permissions.
- A custom `unconfined` domain for a specific signing identity cannot be expressed — the domain transition depends on the binary path, not the certificate.

---

## MDM-managed policy

ClearanceKit policies can be delivered via an Apple Configuration Profile (MDM), which creates a read-only managed tier visible in the GUI alongside user-created rules. The profile is a structured plist validated against a defined schema.

SELinux policies are distributed as compiled policy modules (`.pp` files) installed by the system administrator. There is no equivalent of MDM push — each managed host must receive and install the policy module independently, typically via a configuration management tool such as Ansible, Puppet, or Chef.

---

## Summary

ClearanceKit and SELinux both implement kernel-enforced MAC, but they make different trade-offs suited to their respective platforms and threat models.

**ClearanceKit strengths relative to SELinux:**

- **Cryptographic process identity.** Policies survive a trojanised binary replacement and every software update without maintenance.
- **Process ancestry.** Rules can require that a trusted process is present anywhere in the call chain, not just as the immediate caller.
- **Zero-maintenance across updates.** Signing identity is stable; file hashes are not.
- **GUI-driven policy discovery.** Denied events surface immediately so policies can be built incrementally from real workload observations.

**SELinux strengths relative to ClearanceKit:**

- **Broader scope.** SELinux controls far more than file access — network sockets, IPC, capability use, memory mapping, and more.
- **Platform independence.** Runs on any Linux distribution, not tied to a specific vendor's signing infrastructure.
- **Established tooling ecosystem.** Decades of tooling for audit log analysis, policy generation (`audit2allow`), and confinement of system services.
- **Multi-level security (MLS/MCS).** Bell–LaPadula confidentiality and Biba integrity models are built in; ClearanceKit has no equivalent.

**Approximating ClearanceKit features in SELinux:**

| ClearanceKit feature | SELinux equivalent | Gap |
|---|---|---|
| FAAPolicy (protect a path by signing identity) | Custom domain + labelled file contexts | Domain transition is path-based, not signature-based |
| Jail rule (confine a process to path prefixes) | Tightly scoped domain with minimal `allow` rules | Requires explicit labelling of every allowed path; unlabelled paths need careful attention |
| Code signing identity | IMA/EVM + RSA-signed per-binary xattrs | Every update invalidates signatures; significant operational overhead |
| Process ancestry allowlist | Not available | No native ancestry-aware policy construct |
| Global allowlist (bypass all rules) | `unconfined_t` or custom broad domain | Cannot scope bypass to a specific signing identity |
| MDM-managed policy | Policy modules via configuration management | No push-based managed tier; each host must be updated independently |
