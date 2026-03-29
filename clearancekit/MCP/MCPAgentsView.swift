//
//  MCPAgentsView.swift
//  clearancekit
//

import SwiftUI

struct MCPAgentsView: View {
    @ObservedObject private var store = MCPSessionStore.shared

    var body: some View {
        Group {
            if store.activeSessions.isEmpty {
                ContentUnavailableView(
                    "No Connected Agents",
                    systemImage: "person.badge.key",
                    description: Text("MCP agents authenticate via Touch ID and appear here once connected.")
                )
            } else {
                List(store.activeSessions) { session in
                    MCPAgentRow(session: session)
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
