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
    case exportSanta         = "Santa"
    case exportClearanceKit  = "ClearanceKit (.mobileconfig)"

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
        case .setup:              return "gearshape"
        case .exportSanta:        return "square.and.arrow.up"
        case .exportClearanceKit: return "doc.richtext"
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
                    Section("Export as\u{2026}") {
                        Label(SidebarItem.exportSanta.rawValue, systemImage: SidebarItem.exportSanta.icon)
                            .tag(SidebarItem.exportSanta)
                        Label(SidebarItem.exportClearanceKit.rawValue, systemImage: SidebarItem.exportClearanceKit.icon)
                            .tag(SidebarItem.exportClearanceKit)
                    }
                }
                .navigationSplitViewColumnWidth(min: 160, ideal: 180)
            } detail: {
                switch nav.selection {
                case .events:      EventsWindowView()
                case .policy:      PolicyView()
                case .presets:     PresetsView()
                case .jail:        JailView()
                case .allowlist:   AllowlistView()
                case .processes:   ProcessesView()
                case .processTree: ProcessTreeView()
                case .metrics:     MetricsView()
                case .setup:       SetupView()
                case .exportSanta:        SantaExportView()
                case .exportClearanceKit: ClearanceKitExportView()
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

    var body: some View {
        VStack(spacing: 0) {
            setupStepsHeader
            Divider()
            extensionStatusRow
            Divider()
            fullDiskAccessRow
            Divider()
            connectionStatusRow
            Spacer()
            Divider()
            versionRow
        }
        .navigationTitle("Setup")
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
                Button("Update") { extensionManager.replaceExtension() }
            } else {
                Button("Deactivate") { extensionManager.deactivateExtension() }
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

    private var versionRow: some View {
        let marketing = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        return HStack {
            Text("Version \(marketing) (\(BuildInfo.gitHash))")
                .font(.caption)
                .foregroundStyle(.tertiary)
            Spacer()
            Button("Check for updates") {
                openUpdatePage()
            }
            .font(.caption)
            .buttonStyle(.plain)
            .foregroundStyle(Color.accentColor)
        }
        .padding()
    }

    private func openUpdatePage() {
        let cleanHash = BuildInfo.gitHash.trimmingCharacters(in: CharacterSet(charactersIn: "+"))
        var components = URLComponents(string: "https://craigjbass.github.io/clearancekit/update.html")
        components?.queryItems = [URLQueryItem(name: "sha", value: cleanHash)]
        guard let url = components?.url else { return }
        NSWorkspace.shared.open(url)
    }

    private var statusColor: Color {
        xpcClient.isConnected ? .green : .red
    }

    private var statusText: String {
        xpcClient.isConnected ? "Connected" : "Disconnected"
    }

}


#Preview {
    ContentView()
}
