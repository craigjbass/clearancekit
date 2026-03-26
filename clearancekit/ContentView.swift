//
//  ContentView.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import SwiftUI
import AppKit

enum SidebarItem: String, CaseIterable, Identifiable {
    case events      = "Events"
    case policy      = "Policy"
    case presets     = "App Protections"
    case jail        = "Jail"
    case allowlist   = "Allowlist"
    case processes   = "Processes"
    case processTree = "Process Tree"
    case metrics     = "Metrics"
    case setup       = "Setup"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .events:      return "list.bullet"
        case .policy:      return "shield"
        case .presets:     return "lock.app.dashed"
        case .jail:        return "lock.rectangle.on.rectangle"
        case .allowlist:   return "checkmark.shield"
        case .processes:   return "cpu"
        case .processTree: return "list.bullet.indent"
        case .metrics:     return "chart.xyaxis.line"
        case .setup:       return "gearshape"
        }
    }
}

struct ContentView: View {
    @StateObject private var xpcClient = XPCClient.shared
    @StateObject private var extensionManager = SystemExtensionManager.shared
    @ObservedObject private var nav = NavigationState.shared
    @StateObject private var protectionStore = AppProtectionStore.shared
    @State private var signatureIssue: PendingSignatureIssue? = nil

    var body: some View {
        VStack(spacing: 0) {
            if xpcClient.hasServiceVersionMismatch {
                ServiceVersionMismatchBanner {
                    nav.selection = .setup
                }
            }
            NavigationSplitView {
                List(selection: $nav.selection) {
                    Section("Monitor") {
                        Label(SidebarItem.events.rawValue, systemImage: SidebarItem.events.icon)
                            .tag(SidebarItem.events)
                        Label(SidebarItem.processes.rawValue, systemImage: SidebarItem.processes.icon)
                            .tag(SidebarItem.processes)
                        Label(SidebarItem.processTree.rawValue, systemImage: SidebarItem.processTree.icon)
                            .tag(SidebarItem.processTree)
                        Label(SidebarItem.metrics.rawValue, systemImage: SidebarItem.metrics.icon)
                            .tag(SidebarItem.metrics)
                    }
                    Section("Configure") {
                        Label(SidebarItem.policy.rawValue, systemImage: SidebarItem.policy.icon)
                            .tag(SidebarItem.policy)
                        Label(SidebarItem.presets.rawValue, systemImage: SidebarItem.presets.icon)
                            .tag(SidebarItem.presets)
                        Label(SidebarItem.jail.rawValue, systemImage: SidebarItem.jail.icon)
                            .tag(SidebarItem.jail)
                        Label(SidebarItem.allowlist.rawValue, systemImage: SidebarItem.allowlist.icon)
                            .tag(SidebarItem.allowlist)
                        Label(SidebarItem.setup.rawValue, systemImage: SidebarItem.setup.icon)
                            .tag(SidebarItem.setup)
                    }
                }
                .navigationSplitViewColumnWidth(min: 160, ideal: 180)
            } detail: {
                switch nav.selection {
                case .events:    EventsWindowView()
                case .policy:    PolicyView()
                case .presets:   PresetsView()
                case .jail:      JailView()
                case .allowlist: AllowlistView()
                case .processes:   ProcessesView()
                case .processTree: ProcessTreeView()
                case .metrics:     MetricsView()
                case .setup:     SetupView()
                }
            }
        }
        .frame(minWidth: 720, minHeight: 480)
        .onAppear {
            xpcClient.connect()
        }
        .onChange(of: xpcClient.pendingSignatureIssue) { _, issue in
            signatureIssue = issue
        }
        .sheet(item: $signatureIssue) { issue in
            DatabaseSignatureIssueView(issue: issue) { approved in
                xpcClient.resolveSignatureIssue(approved: approved)
            }
            .interactiveDismissDisabled()
        }
        // The binding setter is intentionally a no-op: interactive dismissal is disabled,
        // and the sheet is dismissed only by the Cancel/Finalize actions in DiscoverySessionRow,
        // which call AppProtectionStore.shared.cancelDiscovery() or finalizeDiscovery(_:for:).
        .sheet(item: Binding(get: { protectionStore.activeDiscovery }, set: { _ in })) { session in
            DiscoverySessionRow(session: session)
                .padding()
                .frame(minWidth: 500)
                .interactiveDismissDisabled()
        }
    }
}

// MARK: - ServiceVersionMismatchBanner

private struct ServiceVersionMismatchBanner: View {
    let onSetup: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.yellow)
            Text("Service version mismatch — reactivate the system extension to restore functionality.")
            Spacer()
            Button("Go to Setup", action: onSetup)
                .buttonStyle(.borderedProminent)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(Color(NSColor.windowBackgroundColor))
        Divider()
    }
}

// MARK: - ExtensionAction

private enum ExtensionAction: String, Identifiable {
    case deactivate, update
    var id: String { rawValue }
}

// MARK: - SetupView

struct SetupView: View {
    @StateObject private var xpcClient = XPCClient.shared
    @StateObject private var extensionManager = SystemExtensionManager.shared
    @StateObject private var jailStore = JailStore.shared
    @State private var pendingExtensionAction: ExtensionAction?
    @State private var activeJailedProcesses: [RunningProcessInfo] = []

    var body: some View {
        VStack(spacing: 0) {
            setupStepsHeader
            Divider()
            extensionStatusRow
            Divider()
            fullDiskAccessRow
            Divider()
            connectionStatusRow
            Divider()
            jailToggleRow
            Spacer()
            Divider()
            versionRow
        }
        .navigationTitle("Setup")
        .sheet(item: $pendingExtensionAction) { action in
            JailBreakWarningView(
                action: action,
                activeJailedProcesses: activeJailedProcesses,
                onProceed: {
                    executeExtensionAction(action)
                    pendingExtensionAction = nil
                },
                onCancel: { pendingExtensionAction = nil }
            )
        }
    }

    private var appBuildVersion: String { BuildInfo.gitHash.trimmingCharacters(in: CharacterSet(charactersIn: "+")) }

    private var setupStepsHeader: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("To get started, complete the following steps in order:")
                .font(.callout)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 3) {
                Text("1. Activate the system extension")
                Text("2. Grant Full Disk Access to 'opfilter', which is part of clearancekit")
            }
            .font(.callout)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
    }

    private var fullDiskAccessRow: some View {
        HStack {
            Text("Full Disk Access:")
                .font(.headline)
            Text("Required for opfilter to monitor file access")
                .foregroundStyle(.secondary)
            Spacer()
            Button("Open Privacy & Security") {
                NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
            }
        }
        .padding()
    }

    private var serviceIsOutOfDate: Bool {
        !xpcClient.serviceVersion.isEmpty && cleanHash(xpcClient.serviceVersion) != appBuildVersion
    }

    private func cleanHash(_ hash: String) -> String {
        hash.trimmingCharacters(in: CharacterSet(charactersIn: "+"))
    }

    private var extensionStatusRow: some View {
        HStack {
            Text("Extension:")
                .font(.headline)
            Text(extensionManager.statusMessage)
                .foregroundColor(.secondary)
            if serviceIsOutOfDate {
                Text("v\(xpcClient.serviceVersion)")
                    .foregroundStyle(.orange)
                    .font(.caption)
            }
            Spacer()
            if extensionManager.extensionStatus != .activated {
                Button("Activate") { extensionManager.activateExtension() }
            } else if serviceIsOutOfDate {
                Button("Update") { Task { await prepareExtensionAction(.update) } }
            } else {
                Button("Deactivate") { Task { await prepareExtensionAction(.deactivate) } }
            }
        }
        .padding()
    }

    private var connectionStatusRow: some View {
        HStack {
            Circle()
                .fill(statusColor)
                .frame(width: 10, height: 10)
            Text(statusText)
                .font(.headline)
            Spacer()
            Button("Resync") { xpcClient.requestResync() }
                .disabled(!xpcClient.isConnected)
            Button("Quit GUI") { NSApplication.shared.terminate(nil) }
        }
        .padding()
    }

    private var jailToggleRow: some View {
        HStack {
            Toggle(isOn: Binding(
                get: { jailStore.isEnabled },
                set: { jailStore.setEnabled($0) }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("App Jail:")
                        .font(.headline)
                    Text("Experimental — system performance may be degraded")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.checkbox)
            .disabled(!xpcClient.isConnected)
        }
        .padding()
    }

    private var versionRow: some View {
        let marketing = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        return HStack {
            Text("Version \(marketing) (\(BuildInfo.gitHash))")
                .font(.caption)
                .foregroundStyle(.tertiary)
            Spacer()
        }
        .padding()
    }

    private var statusColor: Color {
        xpcClient.isConnected ? .green : .red
    }

    private var statusText: String {
        xpcClient.isConnected ? "Connected" : "Disconnected"
    }

    private func prepareExtensionAction(_ action: ExtensionAction) async {
        guard !jailStore.userRules.isEmpty else {
            executeExtensionAction(action)
            return
        }
        activeJailedProcesses = await xpcClient.fetchActiveJailedProcesses()
        pendingExtensionAction = action
    }

    private func executeExtensionAction(_ action: ExtensionAction) {
        switch action {
        case .deactivate: extensionManager.deactivateExtension()
        case .update: extensionManager.replaceExtension()
        }
    }
}

// MARK: - JailBreakWarningView

private struct JailBreakWarningView: View {
    let action: ExtensionAction
    let activeJailedProcesses: [RunningProcessInfo]
    let onProceed: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Active Jails Will Be Broken", systemImage: "exclamationmark.triangle.fill")
                .font(.title2.bold())
                .foregroundStyle(.orange)

            Text("\(actionLabel) stops jail enforcement immediately. Any jailed process will gain unrestricted file access until the extension is running again.")

            Divider()

            if activeJailedProcesses.isEmpty {
                Text("No jailed processes are currently running.")
                    .foregroundStyle(.secondary)
            } else {
                Text("Quit these processes first:")
                    .font(.headline)
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(activeJailedProcesses, id: \.pid) { process in
                            HStack {
                                Text(URL(fileURLWithPath: process.path).lastPathComponent)
                                    .font(.body.monospaced())
                                Spacer()
                                Text("PID \(process.pid)")
                                    .foregroundStyle(.secondary)
                                    .font(.caption)
                            }
                            .padding(.horizontal, 8)
                        }
                    }
                    .padding(.vertical, 4)
                }
                .frame(maxHeight: 180)
                .background(Color(NSColor.textBackgroundColor).opacity(0.5))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }

            Spacer(minLength: 0)

            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                    .keyboardShortcut(.cancelAction)
                Button(actionLabel, role: .destructive, action: onProceed)
            }
        }
        .padding(24)
        .frame(width: 440)
    }

    private var actionLabel: String {
        switch action {
        case .deactivate: return "Deactivate Anyway"
        case .update: return "Update Anyway"
        }
    }
}

#Preview {
    ContentView()
}
