---
id: ADR-O02
domain: operations
date: 2026-04-05
status: Accepted
---
# ADR-O02: SLSA L3 Provenance and Sigstore

## Context

Users downloading ClearanceKit binaries from GitHub Releases have no way to verify that the binary they received was built from the published source at the published commit. GitHub's inline `actions/attest-build-provenance` stores attestations out-of-band in GitHub's attestation API, making them invisible to external supply-chain scanners such as OpenSSF Scorecard's Signed-Releases check. Additionally, an attestation produced in the same job as the build cannot honestly claim SLSA Build Level 3, because the signer and builder share the same execution context.

## Options

1. **No provenance** — users cannot verify build integrity. Scorecard Signed-Releases check scores 0/10.
2. **GitHub build attestation only** (`actions/attest-build-provenance`) — easy to add; verifiable via `gh attestation verify`; invisible to Scorecard's asset scanner; cannot claim SLSA L3.
3. **SLSA L3 provenance via `slsa-framework/slsa-github-generator` + Sigstore bundle** — generator runs in an isolated builder job; provenance JSON and Sigstore bundle uploaded as release assets; satisfies Scorecard's Signed-Releases check; enables Rekor transparency log verification.

## Decision

Both the inline GitHub attestation (option 2) and SLSA L3 provenance (option 3) are applied:

The release pipeline is split into three jobs:

1. **`build-and-notarize`** — builds, notarizes, attests with `actions/attest-build-provenance`, stages the Sigstore bundle (`.sigstore`), computes SHA-256 hashes, and uploads DMG and Sigstore bundle as workflow artifacts. Does not interact with GitHub Releases.
2. **`provenance`** — calls `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml` as a reusable workflow. `compile-generator: true` builds the generator binary from source during the run, decoupling the builder identity from any tag reference and allowing SHA pinning. `upload-assets` is not set (the provenance generator handles its own upload separately, and the publish job attaches all assets via a single `gh release create` call). The `.intoto.jsonl` provenance file is uploaded as a workflow artifact.
3. **`publish`** — downloads all artifacts and creates the GitHub release in one atomic `gh release create` call, attaching DMG, `.sigstore`, and `.intoto.jsonl`.

The `provenance` caller job requires `contents: write` because the nested `upload-assets` job inside the generator declares that permission, and GitHub validates all nested job permissions against the caller grant even when `upload-assets` is disabled.

The SLSA generator is pinned by full 40-character commit SHA with `compile-generator: true`.

## Consequences

- Users can verify build provenance end-to-end with `slsa-verifier verify-artifact`.
- The Sigstore bundle enables verification against the Rekor transparency log.
- Scorecard's Signed-Releases check scores 10/10 because the `.sigstore` and `.intoto.jsonl` files appear as release assets.
- `compile-generator: true` adds approximately two minutes to the provenance job but eliminates trust in a pre-built generator binary.
- SHA-pinning the generator satisfies Scorecard's Pinned-Dependencies check for this dependency.
- The three-job structure is required by the immutable releases constraint: all assets must be attached in the single `gh release create` call.
