//
//  ContentView.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import SwiftUI
import AppKit

struct ContentView: View {
    @StateObject private var xpcClient = XPCClient.shared
    @StateObject private var extensionManager = SystemExtensionManager.shared
    @StateObject private var daemonManager = DaemonManager.shared

    var body: some View {
        TabView {
            EventsWindowView()
                .tabItem { Label("Events", systemImage: "list.bullet") }
            PolicyView()
                .tabItem { Label("Policy", systemImage: "shield") }
            ProcessesView()
                .tabItem { Label("Processes", systemImage: "cpu") }
            setupTab
                .tabItem { Label("Setup", systemImage: "gearshape") }
        }
        .frame(minWidth: 640, minHeight: 440)
        .onAppear {
            daemonManager.refreshStatus()
            xpcClient.connect()
        }
    }

    private var setupTab: some View {
        VStack(spacing: 0) {
            daemonStatusBar
            Divider()
            extensionStatusBar
            Divider()
            connectionStatusBar
            Spacer()
        }
    }

    private var daemonStatusBar: some View {
        HStack {
            Text("Daemon:")
                .font(.headline)
            Text(daemonManager.statusMessage)
                .foregroundColor(daemonStatusColor)
            Spacer()
            switch daemonManager.status {
            case .notRegistered, .failed, .unknown:
                Button("Register") {
                    daemonManager.registerDaemon()
                }
            case .requiresApproval:
                Button("Open System Settings") {
                    daemonManager.openSystemSettings()
                }
            case .enabled:
                Button("Unregister") {
                    daemonManager.unregisterDaemon()
                }
            }
        }
        .padding()
    }

    private var daemonStatusColor: Color {
        switch daemonManager.status {
        case .enabled: return .green
        case .requiresApproval: return .yellow
        case .notRegistered, .unknown, .failed: return .red
        }
    }

    private var extensionStatusBar: some View {
        HStack {
            Text("Extension:")
                .font(.headline)
            Text(extensionManager.statusMessage)
                .foregroundColor(.secondary)
            Spacer()
            if extensionManager.extensionStatus != .activated {
                Button("Activate") {
                    extensionManager.activateExtension()
                }
            } else {
                Button("Deactivate") {
                    extensionManager.deactivateExtension()
                }
            }
            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
        }
        .padding()
    }

    private var connectionStatusBar: some View {
        HStack {
            Circle()
                .fill(statusColor)
                .frame(width: 10, height: 10)
            Text(statusText)
                .font(.headline)
            Spacer()
            Button("Resync") {
                xpcClient.requestResync()
            }
            .disabled(!xpcClient.isConnected)
        }
        .padding()
    }

    private var statusColor: Color {
        if xpcClient.isConnected && xpcClient.isMonitoringActive {
            return .green
        } else if xpcClient.isConnected {
            return .yellow
        } else {
            return .red
        }
    }

    private var statusText: String {
        if xpcClient.isConnected && xpcClient.isMonitoringActive {
            return "Connected - Monitoring Active"
        } else if xpcClient.isConnected {
            return "Connected - Monitoring Inactive"
        } else {
            return "Disconnected"
        }
    }
}

#Preview {
    ContentView()
}
