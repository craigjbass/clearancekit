---
id: ADR-O01
domain: operations
date: 2026-03-16
status: Accepted
---
# ADR-O01: GitHub Actions Release Pipeline

## Context

Releasing ClearanceKit requires code-signing with a Developer ID certificate, notarization via Apple's notarytool, stapling the notarization ticket, packaging a DMG, and uploading assets to GitHub Releases. Performing these steps manually is error-prone, hard to audit, and requires Apple API keys and signing certificates to live on a developer machine. Any deviation in the manual process produces a release that may fail Gatekeeper validation or omit required assets.

## Options

1. **Manual releases** — developer runs signing, notarization, DMG packaging, and upload by hand on their own machine. No automation cost; high human error cost; secrets on dev machines.
2. **Fastlane automation** — Fastlane lanes wrap the steps; still runs locally or in CI. Adds a Ruby dependency and Fastlane configuration surface; secrets still need distributing to CI.
3. **GitHub Actions with xcodebuild + notarytool** — a dedicated workflow triggered on version tags runs every step in CI. Secrets stored in GitHub Actions secrets; no developer machine involvement.

## Decision

A GitHub Actions workflow (`release.yml`) triggers on pushes of `v*` tags and runs all release steps across a coordinated multi-job workflow on a `macos-26` runner:

- `xcodebuild archive` produces a Developer ID-signed xcarchive.
- `xcodebuild -exportArchive` with `ExportOptions.plist` exports the signed app.
- `hdiutil` creates a styled drag-and-drop DMG with an Applications symlink, then converts it to a compressed read-only image.
- `xcrun notarytool submit --wait` submits to Apple and blocks until notarization completes.
- `xcrun stapler staple` attaches the notarization ticket to the DMG.
- `gh release create` publishes the release with all assets in one step.

Top-level `permissions: contents: read` establishes least privilege as the default; jobs that require write access declare it explicitly at the job level. The tag name is passed through a `TAG_NAME` environment variable rather than being interpolated directly into `run:` blocks, preventing script injection via a crafted tag name (fixes #113). Build provenance attestation is attached via `actions/attest-build-provenance`.

## Consequences

- Releases are produced exclusively by CI. `CLAUDE.md` documents that manually creating releases (including drafts) is forbidden, as the repository has immutable releases enabled.
- Release notes are editable post-creation via `gh release edit <tag> --notes "..."` without violating the immutability constraint.
- All signing secrets and Apple API credentials live only in GitHub Actions secrets — never on developer machines.
- The styled DMG (grey background, 128 px icons, Applications symlink positioned via AppleScript) provides a standard macOS installer experience.
- Every release includes a build provenance attestation verifiable via `gh attestation verify`.
