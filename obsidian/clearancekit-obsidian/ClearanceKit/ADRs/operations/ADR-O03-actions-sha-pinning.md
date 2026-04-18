---
id: ADR-O03
domain: operations
date: 2026-04-05
status: Accepted
---
# ADR-O03: GitHub Actions SHA Pinning

## Context

GitHub Actions version tags such as `@v3` and `@v4` are mutable — a tag owner can silently repoint a tag to a different commit, including one containing malicious code. Any workflow that references an action by tag is therefore vulnerable to a supply-chain attack in which the action publisher (or an attacker who has compromised the publisher's account) pushes malicious code to the tag. The repository workflow files would show no change, making the attack invisible in code review. OpenSSF Scorecard's Pinned-Dependencies check flags every unpinned action reference.

## Options

1. **Version tags (`@v3`, `@v4`)** — readable and low-maintenance, but vulnerable to tag hijack without any visible repository change.
2. **Branch names (`@main`)** — follows the latest commit on a branch; even more mutable than tags; effectively no version control on the dependency.
3. **Full 40-character commit SHA** — immutable; the referenced commit cannot change; supply-chain attacks require a compromise of the repository hosting the action, not just its tags.

## Decision

Every GitHub Action in every workflow is pinned by its full 40-character commit SHA. The human-readable version tag is preserved as an inline comment on the same line:

```yaml
uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
```

Pip dependencies used in the GitHub Pages build script (`pages-requirements.txt`) are hash-pinned using `--require-hashes` in the pip install invocation, providing equivalent protection for Python dependencies.

Dependabot is configured (see ADR-O06) to keep SHA pins current automatically across all workflows and the pip requirements file. This prevents the maintenance burden of manual SHA updates from causing pins to stagnate on vulnerable versions.

The SLSA generator (`slsa-framework/slsa-github-generator`) requires `compile-generator: true` to allow SHA pinning without breaking the builder identity embedded in the provenance attestation (see ADR-O02).

## Consequences

- Immune to tag-hijack and branch-force-push supply-chain attacks on third-party action publishers.
- Scorecard's Pinned-Dependencies check scores 10/10.
- Dependabot automation is a hard requirement: updating 10+ SHA pins across multiple workflow files manually is impractical and would be neglected.
- SHA comments (`# v4.3.1`) degrade over time if SHAs are updated without updating the comment; Dependabot updates both simultaneously.
- The `compile-generator: true` flag on the SLSA generator adds ~2 minutes to the provenance job as the trade-off for allowing SHA pinning on that dependency.
