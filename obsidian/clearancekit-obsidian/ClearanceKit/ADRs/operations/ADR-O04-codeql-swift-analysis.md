---
id: ADR-O04
domain: operations
date: 2026-04-05
status: Superseded
supersededBy: ADR-O05
---
# ADR-O04: CodeQL Swift Analysis

Superseded by [[ADRs/operations/ADR-O05-sonarcloud-analysis]].

## Context

CodeQL was evaluated as a potential SAST tool for Swift. Its integration was trialed but eventually removed. GitHub's CodeQL analysis engine offers deep semantic analysis of Swift source code, complementing SonarCloud's pattern-based checks with data-flow and taint-tracking queries. While active, CodeQL results appeared in the GitHub Security tab and could be enforced as required status checks on pull requests. The workflow (`codeql.yml`) was deleted after determining CodeQL did not meet the project's CI performance requirements.

## Options

1. **No CodeQL** — misses semantic vulnerability patterns detectable only with data-flow analysis.
2. **Auto build mode** — CodeQL infers the build command. For Swift projects this invokes an instrumented `swiftc` wrapper, which proved prohibitively slow (~21 minutes per run) even with zero external dependencies.
3. **Manual build mode** — an explicit `xcodebuild` invocation replaces the autobuild inference. Requires maintaining a correct build invocation in the workflow; suffered from the same performance characteristics as auto mode.
4. **Buildless extraction (`build-mode: none`)** — CodeQL parses Swift source directly without compiling. Faster (seconds vs. 21 minutes) at the cost of slightly less precise data-flow results.

## Decision

CodeQL was added with a matrix covering `swift` and `actions` languages. The workflow iterated through build modes:

- Initial configuration used `autobuild` for Swift on `macos-latest`.
- Runner was changed to `macos-26` with Xcode 26 to match the rest of the project's toolchain (`053aa03`).
- Auto build mode was replaced with manual build mode when autobuild proved unreliable against Xcode 26 (`9bf3d64`).
- Manual build mode was replaced with `build-mode: none` (buildless extraction) after autobuild took ~21 minutes; buildless extraction reduced analysis to seconds (`d203f0e`).
- All actions pinned by SHA (`2441e70`). Top-level least-privilege `permissions: contents: read` block added.

The workflow (`codeql.yml`) was subsequently deleted (`4343a17`) after determining that CodeQL was too slow even in buildless mode for the project's CI requirements.

## Consequences

- CodeQL analysis was delivered on every push to main and on pull requests while the workflow was active.
- Buildless mode traded some data-flow analysis depth for reliability on Swift projects with complex build graphs.
- The decision to delete the workflow reflects the practical trade-off between analysis depth and CI cycle time for a solo project.
- Results that were produced appeared in the GitHub Security tab.
- The history of build-mode iteration (auto → manual → buildless → deleted) informs future re-evaluation should faster Swift CodeQL extraction become available.
