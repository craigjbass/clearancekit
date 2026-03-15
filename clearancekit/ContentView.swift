//
//  ContentView.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import SwiftUI
import AppKit

enum SidebarItem: String, CaseIterable, Identifiable {
    case events     = "Events"
    case policy     = "Policy"
    case presets    = "App Protections"
    case allowlist  = "Allowlist"
    case processes  = "Processes"
    case setup      = "Setup"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .events:    return "list.bullet"
        case .policy:    return "shield"
        case .presets:   return "lock.shield"
        case .allowlist: return "checkmark.shield"
        case .processes: return "cpu"
        case .setup:     return "gearshape"
        }
    }
}

struct ContentView: View {
    @StateObject private var xpcClient = XPCClient.shared
    @StateObject private var extensionManager = SystemExtensionManager.shared
    @StateObject private var daemonManager = DaemonManager.shared
    @ObservedObject private var nav = NavigationState.shared

    var body: some View {
        VStack(spacing: 0) {
            if xpcClient.hasDaemonVersionMismatch {
                DaemonVersionMismatchBanner {
                    nav.selection = .setup
                }
            }
            NavigationSplitView {
                List(SidebarItem.allCases, selection: $nav.selection) { item in
                    Label(item.rawValue, systemImage: item.icon)
                        .tag(item)
                }
                .navigationSplitViewColumnWidth(min: 160, ideal: 180)
            } detail: {
                switch nav.selection {
                case .events:    EventsWindowView()
                case .policy:    PolicyView()
                case .presets:   PresetsView()
                case .allowlist: AllowlistView()
                case .processes: ProcessesView()
                case .setup:     SetupView()
                }
            }
        }
        .frame(minWidth: 720, minHeight: 480)
        .onAppear {
            daemonManager.refreshStatus()
            xpcClient.connect()
        }
    }
}

// MARK: - DaemonVersionMismatchBanner

private struct DaemonVersionMismatchBanner: View {
    let onSetup: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.yellow)
            Text("Daemon version mismatch — re-register the daemon to restore functionality.")
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

// MARK: - SetupView

struct SetupView: View {
    @StateObject private var xpcClient = XPCClient.shared
    @StateObject private var extensionManager = SystemExtensionManager.shared
    @StateObject private var daemonManager = DaemonManager.shared

    var body: some View {
        VStack(spacing: 0) {
            daemonStatusRow
            Divider()
            extensionStatusRow
            Divider()
            connectionStatusRow
            Spacer()
            Divider()
            versionRow
        }
        .navigationTitle("Setup")
    }

    private var daemonStatusRow: some View {
        HStack {
            Text("Daemon:")
                .font(.headline)
            Text(daemonManager.statusMessage)
                .foregroundColor(daemonStatusColor)
            Spacer()
            switch daemonManager.status {
            case .notRegistered, .failed, .unknown:
                Button("Register") { daemonManager.registerDaemon() }
            case .requiresApproval:
                Button("Open System Settings") { daemonManager.openSystemSettings() }
            case .enabled:
                Button("Unregister") { daemonManager.unregisterDaemon() }
            }
        }
        .padding()
    }

    private var daemonStatusColor: Color {
        switch daemonManager.status {
        case .enabled:                          return .green
        case .requiresApproval:                 return .yellow
        case .notRegistered, .unknown, .failed: return .red
        }
    }

    private var extensionStatusRow: some View {
        HStack {
            Text("Extension:")
                .font(.headline)
            Text(extensionManager.statusMessage)
                .foregroundColor(.secondary)
            Spacer()
            if extensionManager.extensionStatus != .activated {
                Button("Activate") { extensionManager.activateExtension() }
            } else {
                Button("Deactivate") { extensionManager.deactivateExtension() }
            }
            Button("Quit") { NSApplication.shared.terminate(nil) }
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
        if xpcClient.isConnected && xpcClient.isMonitoringActive { return .green }
        if xpcClient.isConnected { return .yellow }
        return .red
    }

    private var statusText: String {
        if xpcClient.isConnected && xpcClient.isMonitoringActive { return "Connected - Monitoring Active" }
        if xpcClient.isConnected { return "Connected - Monitoring Inactive" }
        return "Disconnected"
    }
}

#Preview {
    ContentView()
}
