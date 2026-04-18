---
id: ADR-O08
domain: operations
date: 2026-03-21
status: Accepted
---
# ADR-O08: Prerelease Versioning Strategy

## Context

Every commit to main produces a fully notarized, signed build via the CI pipeline. Contributors and testers need access to these builds without waiting for a stable release to be tagged. Prerelease version numbers must be distinguishable from stable releases at a glance, sortable, and must not interfere with the version computation for stable releases.

## Options

1. **Stable releases only** — no prerelease builds available between stable tags; testers must build locally or wait for a stable release.
2. **Nightly builds with date suffix** — e.g., `v4.2-nightly-20260321`. Date-based; does not convey relationship to the next stable version; confusing when multiple commits land on the same day.
3. **Prerelease tags based on next patch version increment + git SHA suffix** — e.g., `v4.2.4-beta-abc1234`. Signals the minimum version the next stable release will be; SHA suffix uniquely identifies the commit.

## Decision

A separate `prerelease.yml` workflow triggers on every push to main. It computes a version name of the form `v<MARKETING_VERSION>.<NEXT_PATCH>-beta-<sha7>`:

- `MARKETING_VERSION` is read from the Xcode project's `MARKETING_VERSION` setting (the `major.minor` component).
- `NEXT_PATCH` is computed by finding the highest patch number among existing stable tags matching `v<MARKETING_VERSION>.*`, then adding one. The script variables are named `LAST_MINOR` and `NEXT_MINOR` but they represent the third semver component (the patch number), not the minor version. `-beta-` tags are explicitly filtered out from this list (`grep -v -- '-beta-'`) to prevent double-incrementing when the last tag is itself a prerelease.
- `sha7` is the 7-character short SHA produced by `git rev-parse --short HEAD` (the default length).

The release is created with `gh release create --prerelease`. The workflow runs the same build, sign, notarize, DMG packaging, and attestation steps as the stable release workflow.

The initial implementation incremented from the last prerelease tag's patch number (`7560b10`). This was corrected by Copilot to base the increment on the last stable release instead (`50e449e`), then further corrected to explicitly filter `-beta-` tags during version computation (`ff28410`).

## Consequences

- Every commit to main produces a testable, notarized prerelease within CI cycle time.
- The version format (`v4.2.4-beta-abc1234`) communicates that the next stable release will be at least `v4.2.4`, giving testers meaningful version context.
- Stable releases use clean semver tags; prerelease tags are distinguishable by the `-beta-` infix.
- The `-beta-` filter in the version computation script prevents version number loops that would otherwise occur after many prereleases without a stable release.
- GitHub's `--prerelease` flag keeps prerelease builds visually distinct in the Releases UI from stable releases.
