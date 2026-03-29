//
//  MCPSessionStore.swift
//  clearancekit
//

import Foundation
import Combine

@MainActor
final class MCPSessionStore: ObservableObject {
    static let shared = MCPSessionStore()

    struct MCPSession: Identifiable {
        let id: UUID
        let clientName: String
        let clientVersion: String
        let connectedAt: Date
        var lastActivityAt: Date
        var toolCallCount: Int
        var lastTool: String?
        // Closes the underlying socket when revoked.
        let closeFn: @Sendable () -> Void
    }

    @Published private(set) var activeSessions: [MCPSession] = []

    /// Prompts for Touch ID, then registers the connection as an active session.
    /// Throws if authentication is cancelled or fails.
    func issueSession(
        clientName: String,
        clientVersion: String,
        closeFn: @escaping @Sendable () -> Void
    ) async throws -> UUID {
        try await BiometricAuth.authenticate(reason: "Allow \"\(clientName)\" to connect to ClearanceKit MCP")
        let session = MCPSession(
            id: UUID(),
            clientName: clientName,
            clientVersion: clientVersion,
            connectedAt: Date(),
            lastActivityAt: Date(),
            toolCallCount: 0,
            lastTool: nil,
            closeFn: closeFn
        )
        activeSessions.append(session)
        return session.id
    }

    func isValid(_ id: UUID) -> Bool {
        activeSessions.contains { $0.id == id }
    }

    func recordToolCall(sessionID: UUID, tool: String) {
        guard let i = activeSessions.firstIndex(where: { $0.id == sessionID }) else { return }
        activeSessions[i].lastActivityAt = Date()
        activeSessions[i].toolCallCount += 1
        activeSessions[i].lastTool = tool
    }

    /// Revokes the session and forcibly closes the underlying socket connection.
    func revoke(_ id: UUID) {
        activeSessions.first(where: { $0.id == id })?.closeFn()
        activeSessions.removeAll { $0.id == id }
    }

    /// Called when the remote end closes the connection normally.
    func connectionClosed(_ id: UUID) {
        activeSessions.removeAll { $0.id == id }
    }
}
