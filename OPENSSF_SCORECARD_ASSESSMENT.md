# OpenSSF Scorecard Assessment

**Score:** 6.8 / 10
**Assessed commit:** `ccb76b9`
**Generated:** 2026-04-09

---

## Risk Register

| Check | Score | Severity | Status | Mitigation / Treatment |
|---|---|---|---|---|
| **Code-Review** | 0/10 | High | Accepted (trunk-based dev) | Project uses trunk-based development with a single maintainer. The scorer only recognises PR-based review. Compensating control: each release is cut from a stable `main` build and the full diff between release tags is reviewed before tagging. This is documented here as the accepted process; no workflow change planned. |
| **Maintained** | 0/10 | High | Accepted (solo project) | The scorer flags inactivity based on commit cadence and issue response time. Document the maintenance status explicitly in README (e.g. "active but low-traffic"). Close or triage stale issues to signal responsiveness. |
| **Branch-Protection** | 3/10 | High | Accepted | Force-pushes and deletion are already disabled on `main`, and branch protection applies to administrators. The remaining scorer warnings (no status checks, no PR requirement, codeowners review undetectable) all require a PR-based workflow to satisfy. These are incompatible with trunk-based development and are accepted. |
| **Fuzzing** | 0/10 | Medium | Accepted (not feasible) | Swift fuzzing tooling does not currently integrate with OSS-Fuzz in a workable way for this project. Risk accepted. Compensating controls: comprehensive unit tests on the parsing and policy evaluation paths most likely to be affected by malformed input. |
| **SAST** | 6/10 | Medium | Partially mitigated | SAST is provided by CodeClimate on every push. The scorer does not fully recognise CodeClimate; score reflects partial detection. No additional tooling planned — CodeClimate coverage is considered sufficient for this project's risk profile. |
| **CII-Best-Practices** | 0/10 | Low | Accepted | Apply for an OpenSSF Best Practices badge at `bestpractices.coreinfrastructure.org`. Most criteria will already be met given existing CI, security policy, and licence. Low effort, improves discoverability and scorer result. |
| **Contributors** | 3/10 | Low | Accepted (solo project) | Score reflects single-organisation contribution. No action required — accept the score as a structural property of a solo project. Document this in the assessment so it is not confused with a real risk. |
| **Packaging** | ? | Medium | Unknown | The scorer could not determine packaging status. If ClearanceKit ships distributable artefacts, publish them as a GitHub Release with a consistent, machine-readable naming scheme. The scorer looks for release assets to infer packaging. |
| **Dangerous-Workflow** | 10/10 | Critical | Mitigated | No action required. |
| **Dependency-Update-Tool** | 10/10 | High | Mitigated | No action required. |
| **Binary-Artifacts** | 10/10 | High | Mitigated | No action required. |
| **Token-Permissions** | 10/10 | High | Mitigated | No action required. |
| **Vulnerabilities** | 10/10 | High | Mitigated | No action required. |
| **Signed-Releases** | 10/10 | High | Mitigated | No action required. |
| **Security-Policy** | 10/10 | Medium | Mitigated | No action required. |
| **Pinned-Dependencies** | 10/10 | Medium | Mitigated | No action required. |
| **License** | 10/10 | Low | Mitigated | No action required. |
| **CI-Tests** | 10/10 | Low | Mitigated | No action required. |

