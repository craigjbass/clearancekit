//
//  MCPAgentsView.swift
//  clearancekit
//

import SwiftUI

struct MCPAgentsView: View {
    @ObservedObject private var store = MCPSessionStore.shared
    @ObservedObject private var xpcClient = XPCClient.shared

    var body: some View {
        VStack(spacing: 0) {
            MCPSecurityWarningView()
                .padding()

            Divider()

            Group {
                if !xpcClient.mcpEnabled {
                    ContentUnavailableView(
                        "MCP Server Disabled",
                        systemImage: "network.slash",
                        description: Text("Enable the MCP server above to allow AI agents to connect.")
                    )
                } else if store.activeSessions.isEmpty {
                    ContentUnavailableView(
                        "No Connected Agents",
                        systemImage: "person.badge.key",
                        description: Text("MCP agents authenticate and appear here once connected.")
                    )
                } else {
                    List(store.activeSessions) { session in
                        MCPAgentRow(session: session)
                    }
                }
            }
        }
        .navigationTitle("MCP Agents")
        .toolbar {
            ToolbarItem(placement: .status) {
                Text(MCPServer.socketPath)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - MCPSecurityWarningView

private struct MCPSecurityWarningView: View {
    @ObservedObject private var xpcClient = XPCClient.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Toggle(isOn: Binding(
                get: { xpcClient.mcpEnabled },
                set: { xpcClient.setMCPEnabled($0) }
            )) {
                Label("Enable MCP Server", systemImage: "network")
                    .font(.headline)
            }
            .toggleStyle(.switch)

            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Security Warning")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundStyle(.orange)
                    Text("The MCP server increases the attack surface of ClearanceKit by exposing policy management over a local socket. Disable it when not in use.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

// MARK: - MCPAgentRow

private struct MCPAgentRow: View {
    let session: MCPSessionStore.MCPSession
    @ObservedObject private var store = MCPSessionStore.shared

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "person.badge.key.fill")
                .foregroundStyle(.blue)
                .imageScale(.large)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(session.clientName)
                        .font(.headline)
                    if !session.clientVersion.isEmpty {
                        Text("v\(session.clientVersion)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.secondary.opacity(0.15))
                            .clipShape(Capsule())
                    }
                }

                HStack(spacing: 12) {
                    Label("Connected \(session.connectedAt, style: .relative) ago", systemImage: "clock")
                    if session.toolCallCount > 0 {
                        Label("\(session.toolCallCount) call\(session.toolCallCount == 1 ? "" : "s")", systemImage: "wrench.and.screwdriver")
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)

                if let lastTool = session.lastTool {
                    Text("Last: \(lastTool)")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            Button("Revoke", role: .destructive) {
                store.revoke(session.id)
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
        .padding(.vertical, 4)
    }
}
