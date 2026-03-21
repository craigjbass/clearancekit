#!/usr/bin/env bash
set -euo pipefail

git fetch --tags

MARKETING_VERSION=$(grep -m1 'MARKETING_VERSION' clearancekit.xcodeproj/project.pbxproj | grep -oE '[0-9]+\.[0-9]+')
SHORT_HASH=$(git rev-parse --short HEAD)

NEXT_INCREMENT=$(git tag --list "v${MARKETING_VERSION}.*" \
    | grep -E "^v${MARKETING_VERSION//./\\.}\.[0-9]+(-[0-9a-f]+)?$" \
    | sed -E "s/^v${MARKETING_VERSION//./\\.}\.([0-9]+).*/\1/" \
    | sort -n \
    | tail -1 \
    || true)

NEXT_INCREMENT=$(( ${NEXT_INCREMENT:-0} + 1 ))

TAG="v${MARKETING_VERSION}.${NEXT_INCREMENT}-${SHORT_HASH}"

git tag "$TAG"
git push origin "$TAG"

echo "$TAG"
