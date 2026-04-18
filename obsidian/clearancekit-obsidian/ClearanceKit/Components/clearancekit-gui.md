# clearancekit (GUI)

The SwiftUI menu-bar application (`uk.craigbass.clearancekit`) users interact with. Its sole job is to talk to `opfilter` over XPC: it displays live events, shows and mutates policy, runs export wizards, and hosts the optional MCP server. It has no direct Endpoint Security, SQLite, or keychain access.

## Role

- Provides the UI surface for policy management. Every mutation round-trips through `opfilter` — the GUI holds no authoritative state.
- Presents live deny events as they arrive from the `ClientProtocol.folderOpened` callback.
- Acts as a user-space notifier for things `opfilter` cannot do: `UNUserNotificationCenter` alerts, sheets for signature-issue resolution, and the Touch ID prompt that gates every policy mutation.
- Runs an optional embedded Model Context Protocol server so local LLM agents can query live events and running processes.

## Window and sidebar structure

The main window is a `NavigationSplitView` defined in `App/ContentView.swift`. The `SidebarItem` enum lists every section; the sidebar groups them under three headings:

### Monitor
- **Events** (`Monitor/Events/EventsWindowView`) — live stream of `FolderOpenEvent` records pushed by opfilter.
- **Tamper Events** (`Monitor/TamperEvents/TamperEventsView`) — denied signals and suspend/resume attempts against opfilter, driven by `tamperAttemptDenied`.
- **Processes** (`Monitor/Processes/ProcessesView`) — live `[RunningProcessInfo]` snapshot sourced from `fetchProcessList`.
- **Process Tree** (`Monitor/ProcessTree/ProcessTreeView`) — hierarchical view backed by `fetchProcessTree`; hosts the wizard sheet that turns a running binary into a rule.
- **Metrics** (`Monitor/Metrics/MetricsView`) — real-time throughput graph built from the `PipelineMetricsSnapshot` stream delivered once per second via `metricsUpdated`.

### Configure
- **Policy** (`Configure/Policy/PolicyView`) — the FAA rule editor. Shows baseline, managed (read-only), and user tiers; uses `RuleEditView` for create/edit. Import and export sheets (`PolicyImportView`, `PolicyExportView`) support backup and migration.
- **App Protections** (`Configure/AppProtections/PresetsView`) — named bundles of rules per application. Covers install/remove of `AppPreset` entries; `ProtectionFettleView` renders drift between an installed preset and the current built-in version (see [[ADRs/features/ADR-F09-preset-drift-detection]]). `ProtectionDraft` models in-progress discovery sessions, and `ManagedAppProtectionLoader` reads MDM-delivered `AppProtections`.
- **Jail** (`Configure/Jail/JailView`) — jail-rule CRUD and toggle for the whole feature. Backed by `JailStore`.
- **Allowlist** (`Configure/Allowlist/AllowlistView`) — immediate-process and ancestor-process bypass entries, managed by `AllowlistStore`.
- **Setup** (`App/ContentView.swift SetupView`) — system-extension activation, Full Disk Access prompt, connection status, and service-version mismatch handling.
- **MCP Agents** (`MCP/MCPAgentsView`) — toggle for the embedded MCP server, plus the session browser backed by `MCPSessionStore`.

### Export as
- **Santa** (`Export/SantaExportView`) — wizard that renders current rules as a Santa-compatible policy file.
- **ClearanceKit (.mobileconfig)** (`Export/ClearanceKitExportView` + `ClearanceKitMobileconfigExporter`) — exports the user policy as an Apple Configuration Profile suitable for MDM deployment.

## XPC-only communication

`App/XPCClient.swift` is the single integration point with opfilter. It is a `@MainActor` `ObservableObject` singleton (`XPCClient.shared`) that:

- Opens an `NSXPCConnection` to `XPCConstants.serviceName` and calls `registerClient`.
- Publishes `@Published` properties (`events`, `tamperEvents`, `metricsHistory`, `mcpEnabled`, `isConnected`, `isServiceReady`, `hasServiceVersionMismatch`, `pendingSignatureIssue`) that every view observes.
- Receives pushes from opfilter via its `ClientProtocol` conformance: `folderOpened`, `managedRulesUpdated`, `userRulesUpdated`, and the rest of the rule/allowlist/jail snapshot callbacks.
- Batches event deliveries into `pendingEvents` and flushes them every three seconds to keep SwiftUI redraws bounded.

All SwiftUI store types — `PolicyStore`, `AllowlistStore`, `JailStore`, `AppProtectionStore` — observe `XPCClient` rather than holding their own state. Writes call through to `XPCClient` methods which forward to opfilter via `ServiceProtocol` (`addRule`, `updateRule`, `removeRule`, `addAllowlistEntry`, `setJailEnabled`, and so on).

## Touch ID on every mutation

`App/BiometricAuth.swift` wraps `LAContext.evaluatePolicy(.deviceOwnerAuthentication, ...)` in an `async throws` function. The store layer calls it before any XPC method that mutates state — adding, updating, or removing a rule, allowlist entry, jail rule, or preset, and before approving a signature-issue resolution. A user cancellation is treated as a silent no-op; any other error surfaces in the UI. See [[ADRs/security/ADR-S02-touch-id-policy-mutations]].

## Preset management and drift detection

`Configure/AppProtections` implements the preset system (see [[ADRs/features/ADR-F04-preset-system]]):

- `AppPreset` is a named bundle of `FAARule` UUIDs for a single application.
- `AppProtection.swift` merges the user's installed preset with the current built-in definition for that app and reports per-rule deltas.
- `ProtectionFettleView` renders the diff so users can accept individual rule updates or reject the preset update entirely.
- The `Presets/` subdirectory holds the built-in presets; the UUIDs in these presets are stable across releases because the database signing system keys on them.

## Export wizards

The GUI can serialise the active policy into two external formats:

- **Santa** — `SantaMobileconfigExporter` (in `Shared/`) emits a Santa `.mobileconfig`. `Export/SantaExportView` drives the user through the selection and save.
- **ClearanceKit mobileconfig** — `ClearanceKitMobileconfigExporter` emits a `uk.craigbass.clearancekit`-domain Configuration Profile that the same opfilter build re-ingests through `ManagedPolicyLoader`. Useful for MDM rollout or sharing a tested rule set between machines.

Both exporters consume `PolicyExportDocument` from `Shared/`, so formatting logic is reusable between the GUI and any future CLI export.
