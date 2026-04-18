---
id: ADR-O05
domain: operations
date: 2026-04-06
status: Accepted
---
# ADR-O05: SonarCloud Static Analysis

## Context

Swift code quality and security scanning requires dedicated tooling beyond Xcode's built-in warnings. Manual code review cannot reliably detect patterns such as duplicated code across files, common vulnerability anti-patterns, or declining quality metrics over time. An objective, automated quality signal visible on every pull request reduces the cost of catching regressions early.

## Options

1. **No static analysis** — relies entirely on code review and compiler warnings. No quality gate; regressions are caught only if a reviewer notices.
2. **SwiftLint only** — enforces style and conventions; produces no security vulnerability detection and no duplication analysis.
3. **SonarCloud** — cloud-hosted static analysis covering code quality, duplication detection, and security vulnerability patterns. Quality Gate result visible on every PR; integrates with GitHub status checks.

## Decision

SonarCloud is configured for the project via `sonar-project.properties`. Test code is excluded from the copy-paste detection (CPD) analysis (`sonar.cpd.exclusions=Tests/**`) because test factory helpers and assertion patterns are intentionally repetitive across test suites — excluding them prevents false positives without reducing coverage of production code.

A standalone GitHub Actions workflow (`sonarcloud.yml`) was initially added to drive the analysis. After initial configuration issues it was replaced with SonarCloud's automatic analysis mode, which analyses on push to main without requiring a workflow file. The standalone workflow was subsequently deleted.

A Quality Gate badge is included in the README. Analysis is triggered on pushes to main.

## Consequences

- Quality Gate result is visible on every PR, providing an objective quality signal without requiring manual inspection.
- Duplication detection is focused on production code only; test exclusion prevents false positives from naturally similar test boilerplate.
- SonarCloud's Quality Gate can be configured to block merges if thresholds are exceeded.
- The switch to automatic analysis mode removed the need to maintain a `sonarcloud.yml` workflow file, reducing configuration surface.
- SonarCloud's automatic analysis mode reads configuration from the SonarCloud web UI, not from `sonar-project.properties`. The `sonar.cpd.exclusions=Tests/**` property in that file is not active in automatic mode; it is retained for reference and would take effect only if a workflow-based analysis is ever used.
- SonarCloud is a third-party cloud service; analysis results depend on its availability and on the project remaining within the free tier.
