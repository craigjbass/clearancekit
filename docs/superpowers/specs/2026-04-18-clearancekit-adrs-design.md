# Design: ClearanceKit ADRs and Documentation in Obsidian

**Date:** 2026-04-18  
**Status:** Approved

## Goal

Process all 621 commits in the ClearanceKit repository and produce:
1. Architecture Decision Records (ADRs) covering both architectural and feature decisions
2. Architecture overview, component descriptions, and glossary — stored in the Obsidian vault at `/Users/craigjbass/Projects/clearancekit/obsidian/clearancekit-obsidian/`

## Vault Structure

```
ClearanceKit/
  Architecture Overview.md
  Glossary.md
  Components/
    opfilter.md
    clearancekit-gui.md
    xpc-layer.md
    policy-engine.md
    process-tree.md
  ADRs/
    architecture/
      ADR-001-hexagonal-architecture.md
      ADR-002-daemon-gui-separation.md
      ADR-003-xpc-ipc-boundary.md
      ADR-004-sqlite-persistence.md
    security/
      ADR-010-policy-signing-ec-p256.md
      ADR-011-touch-id-policy-mutations.md
      ADR-012-xpc-audit-token-validation.md
      ADR-013-tamper-resistance.md
      ADR-014-slsa-l3-provenance.md
    features/
      ADR-020-write-only-rules.md
      ADR-021-managed-policy-tier.md
      ADR-022-global-allowlist.md
      ADR-023-preset-system.md
      ADR-024-process-ancestry.md
      ADR-025-app-protections.md
    operations/
      ADR-030-github-actions-release.md
      ADR-031-notarization.md
      ADR-032-sonarcloud-codeql.md
      ADR-033-dependabot-supply-chain.md
```

## ADR Format

Each ADR uses this template:

```markdown
---
id: ADR-NNN
domain: <architecture|security|features|operations>
date: <date of first relevant commit>
status: Accepted
---
# ADR-NNN: <Title>

## Context
<What situation prompted this decision? What problem was being solved?>

## Options
<What alternatives were considered?>

## Decision
<What was chosen and why?>

## Consequences
<What are the trade-offs, follow-on work, or constraints introduced?>
```

## Execution Strategy

5 parallel agents:

- **Agent 1 (architecture domain):** Analyze commits related to hexagonal arch, daemon/GUI split, XPC boundary, SQLite migration. Write `ADRs/architecture/` files.
- **Agent 2 (security domain):** Analyze commits related to policy signing, Touch ID, audit token validation, tamper resistance, SLSA, Sigstore. Write `ADRs/security/` files.
- **Agent 3 (features domain):** Analyze commits related to write-only rules, managed policy tier, global allowlist, presets, process ancestry, app protections, AccessKind. Write `ADRs/features/` files.
- **Agent 4 (operations domain):** Analyze commits related to CI/CD, notarization, SonarCloud, CodeQL, Dependabot, SLSA workflow. Write `ADRs/operations/` files.
- **Agent 5 (overview + components + glossary):** Read CLAUDE.md, codebase structure, and key source files. Write `Architecture Overview.md`, `Glossary.md`, and all `Components/` notes.

All agents write directly to Obsidian via the `obsidian-mcp-tools` MCP server.

## Estimated Output

~25-30 ADRs across four domains, plus 7 supporting documents (overview, glossary, 5 component notes).

## Commit Clusters by Domain

### Architecture
- `9074ce8` Introduce hexagonal architecture in opfilter
- `5887fd5` Merge daemon into opfilter as single privileged process
- `1a49d9c` Migrate daemon persistence from JSON files to SQLite
- `0a997cd` Move policy storage to daemon
- `c525c98` Move process enumeration from GUI to daemon
- `7b23e09` Secure XPC server with audit_token-based code signing validation
- `588b801` Unify allowlist and policy evaluation under evaluateAccess
- `4d8bb89` Consolidate team ID and signing ID into ProcessSignature pairs

### Security
- `4bb6687` Sign on-disk policy with EC-P256 key
- `e43a3a2` Require Touch ID for all policy mutations
- `7b23e09` Secure XPC server v2 with audit token validation
- `0216b95` Lock down policy signing key ACL and enable Secure Enclave
- `fb88dce` Add ESTamperResistanceAdapter
- `d769c30` Add SLSA L3 provenance and Sigstore bundle
- `243623e` Prevent script injection via tag name in release workflow
- `73a4f68` Pin GitHub Actions by commit SHA

### Features
- `835dc2c` Add enforceOnWriteOnly to FAARule
- `a8b15a23` Add managed profile policy tier
- `9497550` Add global allowlist
- `391f101` Add App Protections tab
- `68e91e9` Track process ancestry
- `d16fc3e` Add preset drift detection
- `ec72fcc` Add 13 new security presets
- `b212a57` Add wildcard support to path patterns
- `2482275` Support universal wildcard *:* in ProcessSignature matching
- `d1798c4` Evaluate rules by most-specific path, not array order

### Operations
- `e28edae` Add GitHub Actions release workflow with notarization
- `89dfe46` Add Dependabot config
- `ca0cb45` Add CodeQL analysis workflow
- `3005356` Configure SonarCloud analysis
- `d769c30` SLSA L3 provenance
- `331cf56` Add Scorecard workflow
