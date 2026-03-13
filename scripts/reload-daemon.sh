#!/bin/bash
# Reloads the clearancekit daemon from the freshly-built app bundle.
# Called as an Xcode post-build action; BUILT_PRODUCTS_DIR is set by Xcode.

set -euo pipefail

DAEMON_LABEL="uk.craigbass.clearancekit.daemon"
PLIST="${BUILT_PRODUCTS_DIR}/clearancekit.app/Contents/Library/LaunchDaemons/${DAEMON_LABEL}.plist"

osascript -e "do shell script \"launchctl bootout system/${DAEMON_LABEL} 2>/dev/null; true; sleep 0.5; launchctl bootstrap system '${PLIST}'\" with administrator privileges"
