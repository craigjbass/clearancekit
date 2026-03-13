# clearancekit

clearancekit is a macOS security tool that monitors file system activity and enforces per-process allow/deny policies. It surfaces deny events from the Endpoint Security framework in a native SwiftUI interface, letting you build and refine policies without writing configuration files.

## Architecture

Three components work together:

- **clearancekit.app** — SwiftUI menu bar app. Manages policies, displays live deny events, and communicates with the daemon over XPC.
- **uk.craigbass.clearancekit.daemon** — LaunchDaemon that runs as root. Subscribes to Endpoint Security events, evaluates policies, and sends deny events to the app via XPC.
- **uk.craigbass.clearancekit.opfilter** — System extension (DriverKit/EndpointSecurity) loaded by the app. Intercepts `ES_EVENT_TYPE_AUTH_OPEN` events and enforces allow/deny decisions in the kernel.

## Dev Setup

### Prerequisites

- Xcode 16+
- Apple Developer account with the **Endpoint Security** entitlement (`com.apple.developer.endpoint-security.client`) provisioned for your team
- Provisioning profiles for all three targets

### One-time machine configuration

The system extension framework normally requires user approval on every update and enforces placement in `/Applications`. Developer mode bypasses both restrictions so builds from DerivedData update automatically and TCC grants persist.

**Apple Silicon — do this once:**

1. Boot to Recovery (hold Power at startup)
2. Open Startup Security Utility → set **Reduced Security** and enable **Allow user management of kernel extensions from identified developers**
3. Boot normally, then run:

```
systemextensionsctl developer on
```

**Intel — do this once:**

1. Boot to Recovery (hold Cmd+R at startup)
2. In Terminal:

```
csrutil enable --without-fs --without-debug --without-nvram
```

3. Boot normally, then run:

```
systemextensionsctl developer on
```

### First-time activation

1. Build and run the app (Cmd+R) — copies the app to DerivedData and reloads the daemon via the post-build action (one admin password prompt)
2. Open the app and go to the **Setup** tab
3. Click **Activate Extension** — macOS prompts for approval in System Settings (only needed once)
4. Click **Register Daemon** if it is not already running

### Ongoing dev loop

After the one-time setup, each iteration is just:

1. **Cmd+B** or **Cmd+R** in Xcode
2. The post-build action reloads the daemon from the freshly-built bundle (one admin prompt per login session)
3. The system extension updates automatically (developer mode)
4. TCC grants are persistent — no need to re-grant

No copying to `/Applications`, no `launchctl` commands, no extension deactivation.

### Attaching the debugger

**Daemon:** In Xcode, use **Debug → Attach to Process by PID or Name** and enter `uk.craigbass.clearancekit.daemon`. Build first so symbols are current.

**System extension:** Same approach — attach to `uk.craigbass.clearancekit.opfilter`. Note that attaching to an ES client can cause watchdog timeouts; use `ES_OSLOG_LEVEL=debug` logging as a lower-overhead alternative.

## Troubleshooting

Check daemon status:

```
launchctl print system/uk.craigbass.clearancekit.daemon
```

Manually unload the daemon:

```
sudo launchctl bootout system/uk.craigbass.clearancekit.daemon
```

Manually load the daemon (replace `<path>` with the actual plist path):

```
sudo launchctl bootstrap system <path>/clearancekit.app/Contents/Library/LaunchDaemons/uk.craigbass.clearancekit.daemon.plist
```

Check system extension state:

```
systemextensionsctl list
```

Re-enable developer mode after an OS update:

```
systemextensionsctl developer on
```
