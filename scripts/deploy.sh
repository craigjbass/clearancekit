#!/bin/bash
# Deploys the freshly-built app to /Applications, reloads the daemon, and relaunches the app.
# Called as an Xcode post-build action; BUILT_PRODUCTS_DIR is set by Xcode.
#
# Without systemextensionsctl developer mode, the system extension requires one
# manual approval in System Settings after each build that changes the extension.

set -euo pipefail

DAEMON_LABEL="uk.craigbass.clearancekit.daemon"
APP_NAME="clearancekit.app"
SRC="${BUILT_PRODUCTS_DIR}/${APP_NAME}"
DEST="/Applications/${APP_NAME}"
PLIST="${DEST}/Contents/Library/LaunchDaemons/${DAEMON_LABEL}.plist"

osascript -e "do shell script \"cp -R '${SRC}' '${DEST}'\" with administrator privileges"

pkill -x clearancekit 2>/dev/null || true

osascript -e "do shell script \"launchctl bootout system/${DAEMON_LABEL} 2>/dev/null; true; sleep 0.5; launchctl bootstrap system '${PLIST}'\" with administrator privileges"

open "${DEST}"
