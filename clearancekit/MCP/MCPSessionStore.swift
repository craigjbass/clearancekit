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

    /// Prompts for authentication and returns a fresh session ID. Does NOT add the
    /// session to `activeSessions` — the caller must call `commitSession` once the
    /// initialize response has been written and the client has confirmed the
    /// handshake. This avoids briefly showing a session row in the UI for a peer
    /// that has already disconnected.
    func issueSession(
        clientName: String,
        isStillConnected: @Sendable () -> Bool
    ) async throws -> UUID {
        try await BiometricAuth.authenticate(reason: "Allow \"\(clientName)\" to connect to ClearanceKit MCP")
        guard isStillConnected() else {
            throw MCPSessionError.connectionClosedDuringAuthentication
        }
        return UUID()
    }

    /// Adds a previously-issued session to `activeSessions`, making it visible in
    /// the UI and accepted by `isValid`. Must only be called after the MCP
    /// `notifications/initialized` confirms the handshake.
    func commitSession(
        id: UUID,
        clientName: String,
        clientVersion: String,
        closeFn: @escaping @Sendable () -> Void
    ) {
        let session = MCPSession(
            id: id,
            clientName: clientName,
            clientVersion: clientVersion,
            connectedAt: Date(),
            lastActivityAt: Date(),
            toolCallCount: 0,
            lastTool: nil,
            closeFn: closeFn
        )
        activeSessions.append(session)
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

enum MCPSessionError: LocalizedError {
    case connectionClosedDuringAuthentication

    var errorDescription: String? {
        switch self {
        case .connectionClosedDuringAuthentication:
            return "Connection closed before authentication completed"
        }
    }
}
