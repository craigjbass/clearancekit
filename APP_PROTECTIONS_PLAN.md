# 5.0 App Protections Plan — Apple Built-in Apps

## Background

ClearanceKit already ships presets for Notes and Safari. This plan extends coverage to
the remaining high-value Apple built-in apps, prioritised by data sensitivity and
implementation confidence.

Each preset requires two things to be correct before shipping:

1. **File paths** — the directories that hold the app's persistent data.
2. **Signing ID list** — every legitimate process (app, extension, daemon, Spotlight
   indexer, CloudKit sync agent, etc.) that needs read access to those paths. A missing
   entry breaks the app silently; an over-broad entry defeats the protection.

The safest way to build the signing ID list is empirically: protect the path, use
ClearanceKit's discovery session to observe what actually opens it during normal use,
then encode those signatures into the preset.

---

## Pattern

```swift
let fooPreset = AppPreset(
    id: "foo-data-protection",
    appName: "Foo",
    appBundlePath: "/System/Applications/Foo.app",
    description: "…",
    rules: [
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-00XX-0001-0001-000000000001")!,
            protectedPathPrefix: "/Users/*/Library/Foo",
            allowedSignatures: [ apple("com.apple.Foo"), … ]
        ),
    ]
)
```

All Apple platform binaries use `apple(signingID)` (team ID `""` mapped to
`appleTeamID`). Third-party helpers use `sig(teamID, signingID)`.

---

## Tier 1 — Implement first

High data sensitivity, well-understood paths, bounded process surface.

### 1. Mail

| Path | Notes |
|------|-------|
| `/Users/*/Library/Mail` | Mail store (versioned subdirectories V10+) |
| `/Users/*/Library/Containers/com.apple.mail` | Sandboxed container |
| `/Users/*/Library/Group Containers/group.com.apple.mail.shared` | Shared group |

Known process candidates (to verify empirically):
- `com.apple.mail` — main app
- `com.apple.MailServiceAgent`
- `com.apple.MailTrafficAgent`
- `com.apple.mail.XPCHelper`
- `com.apple.exchange.exchangesyncd`
- `com.apple.accountsd`
- `com.apple.cloudd`
- `com.apple.mds` / `com.apple.mds_stores` — Spotlight indexers
- `com.apple.IMCore` — unified accounts layer

**Status:** [x] paths verified  [x] signing IDs verified  [x] preset written  [x] tested

Baked as `mailPreset` in `clearancekit/Configure/AppProtections/Presets/Mail.swift`.
Empirically validated via discovery session. Global allowlist entries removed (`mds`,
`mdworker_shared`, `secinitd`, `containermanagerd`, `WebKit.Networking`). Redundant
`com.apple.cloudd` and `syncdefaultsd` entries cleaned up post-audit.

---

### 2. Contacts

| Path | Notes |
|------|-------|
| `/Users/*/Library/Application Support/AddressBook` | Legacy store |
| `/Users/*/Library/Containers/com.apple.AddressBook` | Sandboxed container |
| `/Users/*/Library/Group Containers/group.com.apple.AddressBook` | Shared group |

Known process candidates:
- `com.apple.AddressBook` — main app
- `com.apple.ContactsAgent` — background sync daemon
- `com.apple.accountsd`
- `com.apple.cloudd`
- `com.apple.mds` — Spotlight

**Status:** [ ] paths verified  [ ] signing IDs verified  [ ] preset written  [ ] tested

---

### 3. Calendar

| Path | Notes |
|------|-------|
| `/Users/*/Library/Calendars` | Calendar store |
| `/Users/*/Library/Containers/com.apple.iCal` | Sandboxed container |
| `/Users/*/Library/Group Containers/group.com.apple.calendar` | Shared group |

Known process candidates:
- `com.apple.iCal` — main app
- `com.apple.CalendarAgent`
- `com.apple.calaccessd`
- `com.apple.accountsd`
- `com.apple.cloudd`
- `com.apple.mds` — Spotlight

**Status:** [ ] paths verified  [ ] signing IDs verified  [ ] preset written  [ ] tested

---

### 4. Reminders

| Path | Notes |
|------|-------|
| `/Users/*/Library/Reminders` | Reminders store |
| `/Users/*/Library/Containers/com.apple.remindd` | Daemon container |
| `/Users/*/Library/Group Containers/group.com.apple.reminders` | Shared group |

Known process candidates:
- `com.apple.reminders` — main app
- `com.apple.remindd` — background daemon
- `com.apple.accountsd`
- `com.apple.cloudd`

**Status:** [ ] paths verified  [ ] signing IDs verified  [ ] preset written  [ ] tested

---

## Tier 2 — After Tier 1 validation

More complex process surfaces or platform constraints that need extra care.

### 5. Messages

| Path | Notes |
|------|-------|
| `/Users/*/Library/Messages` | chat.db + Attachments |
| `/Users/*/Library/Containers/com.apple.iChat` | Sandboxed container |

⚠️ Complex — Messages shares infrastructure with FaceTime, Phone, and several
continuity daemons. Expect a large signing ID list. Needs thorough discovery session
before coding.

**Status:** [ ] paths verified  [ ] signing IDs verified  [ ] preset written  [ ] tested

---

### 6. Photos

| Path | Notes |
|------|-------|
| `/Users/*/Pictures/Photos Library.photoslibrary` | Main library bundle — path contains spaces, verify glob behaviour |
| `/Users/*/Library/Containers/com.apple.Photos` | App container |
| `/Users/*/Library/Group Containers/group.com.apple.Photos` | Shared group |

⚠️ The photoslibrary path contains spaces — confirm FAA prefix matching handles this
correctly before shipping. Also expect `com.apple.photoanalysisd`,
`com.apple.photolibraryd`, `com.apple.mediaanalysisd` in the signing list.

**Status:** [ ] paths verified  [ ] signing IDs verified  [ ] preset written  [ ] tested

---

### 7. Passwords

| Path | Notes |
|------|-------|
| `/Users/*/Library/Containers/com.apple.Passwords` | App container |

⚠️ macOS 15 (Sequoia) and later only. Gate the preset on `resolvedBundlePath` returning
non-nil (i.e. `isInstalled`). Passwords stores credentials via the system Keychain; the
container itself holds UI state and settings — still worth protecting from enumeration.

**Status:** [ ] paths verified  [ ] signing IDs verified  [ ] preset written  [ ] tested

---

## Tier 3 — Lower priority

| App | Key path | Blocker |
|-----|----------|---------|
| Maps | `~/Library/Containers/com.apple.Maps` | Lower sensitivity |
| FaceTime | `~/Library/Containers/com.apple.FaceTime` | Overlaps Messages infrastructure |
| Music | `~/Music/Music`, `~/Library/Containers/com.apple.Music` | Complex DRM/sync daemons |
| Terminal | `~/Library/Application Support/com.apple.Terminal` | Shell history only; lower value |

---

## Research process for each preset

1. Add the target paths as bare FAA rules (no allowed signatures) in a dev build.
2. Launch the app and use it normally for 5–10 minutes, including iCloud sync.
3. Inspect the deny events in ClearanceKit's Events view to collect all signing IDs.
4. Repeat after a reboot to catch launch-time daemons.
5. Encode the collected signatures into the preset file.
6. Re-enable the rule with the full signature list and verify no denies remain during
   normal use.

---

## UUID allocation

Presets use deterministic UUIDs in the range `A1B2C3D4-00XX-0001-0001-000000000YYY`
where `XX` is the preset number and `YYY` is the rule index within that preset.

| Preset | XX |
|--------|----|
| Safari | 01 |
| Notes | 02 |
| Mail | 03 |
| Contacts | 04 |
| Calendar | 05 |
| Reminders | 06 |
| Messages | 07 |
| Photos | 08 |
| Passwords | 09 |
| Maps | 0A |
| FaceTime | 0B |
| Music | 0C |
| Terminal | 0D |
