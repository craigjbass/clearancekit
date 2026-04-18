---
id: ADR-O07
domain: operations
date: 2026-04-05
status: Accepted
---
# ADR-O07: OpenSSF Scorecard

## Context

Supply chain security posture for open-source projects needs objective measurement and public visibility. Enterprise evaluators and security-conscious users increasingly check OpenSSF Scorecard results before adopting a security-sensitive tool. Without a scorecard, there is no systematic way to identify which supply-chain hygiene checks the project passes or fails, or to track improvements over time.

## Options

1. **No scorecard** — no public signal; no systematic check coverage; regressions in workflow configuration go undetected.
2. **Manual security assessment document only** — captures current posture at a point in time; not automated; goes stale without a trigger to refresh.
3. **Automated OpenSSF Scorecard workflow + manual assessment document** — weekly automated run catches configuration regressions; public badge links to live results; manual document explains the rationale for accepted risks and N/A checks.

## Decision

The OpenSSF Scorecard GitHub Actions workflow (`scorecard.yml`) is configured to run weekly on a cron schedule and on every push to main. Results are published to GitHub's Code Scanning dashboard. A badge in the README links to the public scorecard results page.

A manual assessment document (`OPENSSF_SCORECARD_ASSESSMENT.md`) explains the result for each check, documents accepted risks with their rationale, and identifies checks that are not applicable to this project (e.g., Packaging — ClearanceKit distributes via GitHub Releases, not a package registry). The CII Best Practices assessment is included in the same document, covering only the Passing level (Silver and Gold require a bus factor of two or more, which is incompatible with solo development).

The project achieved a score of 6.8/10 at the time of the initial assessment (`ccb76b9`). Accepted risks include Code-Review (trunk-based development with a single maintainer), Branch-Protection (PR workflow requirement incompatible with trunk-based development), Fuzzing (Swift OSS-Fuzz integration not feasible), and Contributors (structural property of a solo project).

## Consequences

- A public scorecard score is visible to users and enterprise evaluators without requiring them to audit the repository manually.
- Automated weekly runs catch regressions introduced by workflow or configuration changes.
- The manual assessment document provides context for N/A checks and accepted risks, preventing low scores from being misread as unmitigated vulnerabilities.
- Checks that score 10/10 (Dangerous-Workflow, Dependency-Update-Tool, Binary-Artifacts, Token-Permissions, Vulnerabilities, Signed-Releases, Security-Policy, Pinned-Dependencies, License, CI-Tests) reflect concrete engineering decisions documented in other ADRs.
- The CII badge provides a complementary supply-chain signal for evaluators who check it.
