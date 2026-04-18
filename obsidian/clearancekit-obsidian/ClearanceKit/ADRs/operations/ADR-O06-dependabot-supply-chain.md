---
id: ADR-O06
domain: operations
date: 2026-04-05
status: Accepted
---
# ADR-O06: Dependabot Supply Chain Management

## Context

SHA-pinning GitHub Actions (ADR-O03) and hash-pinning pip packages used in the GitHub Pages build script eliminates tag-hijack supply-chain risk, but creates a new maintenance burden: pins go stale as upstream actions and packages release patches and security fixes. Tracking and manually updating 10+ pinned SHAs across multiple workflow files is impractical and would likely be neglected, leaving the project on vulnerable versions despite the appearance of being pinned.

## Options

1. **Manual updates** — a maintainer periodically checks for new action versions and updates SHAs by hand. Reliable only with sustained discipline; high probability of neglect in a solo project.
2. **Renovate** — highly configurable; supports monorepos, custom rules, self-hosted deployment. Heavier setup and ongoing configuration burden than Dependabot.
3. **Dependabot** — GitHub-native; zero configuration for GitHub Actions ecosystem; minimal configuration for pip; raises PRs automatically on weekly schedule; integrates with GitHub's auto-merge feature.

## Decision

Dependabot is configured in `.github/dependabot.yml` for two ecosystems:

- **`github-actions`** — weekly schedule, all workflow files in the repository root. Updates are grouped into a single PR covering all action SHA pin changes, reducing review overhead.
- **`pip`** — weekly schedule, targeting `.github/workflows/` where `pages-requirements.txt` lives. Picks up new Pillow releases with refreshed `--hash` values.

Dependabot PRs are reviewed and merged manually.

## Consequences

- SHA pins across all workflows are kept current automatically, maintaining the supply-chain protection of ADR-O03 without manual maintenance.
- Pip hash-pins in `pages-requirements.txt` are refreshed promptly when Pillow releases security patches.
- Scorecard's Dependency-Update-Tool check scores 10/10.
- The grouped GitHub Actions PR reduces review noise versus one PR per action update.
- Dependabot PRs require manual review before merging.
