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
        VStack(spacing: 0) {
            daemonStatusBar
            Divider()
            extensionStatusBar
            Divider()
            connectionStatusBar
            Divider()
            eventList
        }
        .frame(minWidth: 400, minHeight: 300)
        .onAppear {
            daemonManager.refreshStatus()
            xpcClient.connect()
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
        .background(Color(NSColor.windowBackgroundColor))
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
        .background(Color(NSColor.windowBackgroundColor))
    }

    private var connectionStatusBar: some View {
        HStack {
            Circle()
                .fill(statusColor)
                .frame(width: 10, height: 10)
            Text(statusText)
                .font(.headline)
            Spacer()
            if !xpcClient.events.isEmpty {
                Button("Clear") {
                    xpcClient.clearEvents()
                }
                .buttonStyle(.borderless)
            }
        }
        .padding()
        .background(Color(NSColor.windowBackgroundColor))
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

    private var eventList: some View {
        Group {
            if xpcClient.events.isEmpty {
                VStack {
                    Spacer()
                    Text("No file access events yet")
                        .foregroundColor(.secondary)
                    Text("Access a file in /opt/clearancekit to see FAA events")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                }
            } else {
                List(xpcClient.events, id: \.timestamp) { event in
                    EventRow(event: event)
                }
                .listStyle(.inset)
            }
        }
    }
}

struct EventRow: View {
    let event: FolderOpenEvent

    private var formattedTime: String {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .medium
        return formatter.string(from: event.timestamp)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: event.accessAllowed ? "checkmark.shield.fill" : "xmark.shield.fill")
                    .foregroundColor(event.accessAllowed ? .green : .red)
                Text(event.path)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                Spacer()
                Text(event.accessAllowed ? "Allowed" : "Denied")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(event.accessAllowed ? .green : .red)
                Text(formattedTime)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            HStack {
                Text("PID: \(event.processID)")
                    .font(.caption)
                    .foregroundColor(.secondary)
                if !event.processPath.isEmpty {
                    Text(event.processPath)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }
            if !event.teamID.isEmpty || !event.signingID.isEmpty {
                HStack {
                    if !event.teamID.isEmpty {
                        Text("Team: \(event.teamID)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    if !event.signingID.isEmpty {
                        Text("Signing: \(event.signingID)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 4)
        .background(
            RoundedRectangle(cornerRadius: 4)
                .fill(event.accessAllowed ? Color.green.opacity(0.05) : Color.red.opacity(0.1))
        )
    }
}

#Preview {
    ContentView()
}
