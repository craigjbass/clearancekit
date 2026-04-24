//
//  EventBroadcaster.swift
//  opfilter
//
//  Manages connected GUI clients and the recent-event history ring buffer.
//  XPCServer holds one broadcaster and routes both events and state
//  updates through it.
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "event-broadcaster")

// MARK: - EventBroadcaster

final class EventBroadcaster: @unchecked Sendable {
    private struct State {
        var guiClients: [ObjectIdentifier: NSXPCConnection] = [:]
        var allowStreamClients: Set<ObjectIdentifier> = []
        var recentEvents: [FolderOpenEvent] = []
        var recentTamperEvents: [TamperAttemptEvent] = []
    }

    private let storage: OSAllocatedUnfairLock<State>
    private let maxHistoryCount: Int

    init(maxHistoryCount: Int = 1000) {
        self.storage = OSAllocatedUnfairLock(initialState: State())
        self.maxHistoryCount = maxHistoryCount
    }

    // MARK: - Client management

    /// Registers a connection and returns the updated client count.
    @discardableResult
    func addClient(_ connection: NSXPCConnection) -> Int {
        storage.withLock { state in
            state.guiClients[ObjectIdentifier(connection)] = connection
            return state.guiClients.count
        }
    }

    /// Removes a connection and returns the updated client count.
    @discardableResult
    func removeClient(_ connection: NSXPCConnection) -> Int {
        storage.withLock { state in
            let id = ObjectIdentifier(connection)
            state.guiClients.removeValue(forKey: id)
            state.allowStreamClients.remove(id)
            return state.guiClients.count
        }
    }

    // MARK: - Allow-event stream subscription

    @discardableResult
    func beginAllowStream(for connection: NSXPCConnection) -> [FolderOpenEvent] {
        storage.withLock { state in
            state.allowStreamClients.insert(ObjectIdentifier(connection))
            return state.recentEvents.filter(\.accessAllowed).reversed()
        }
    }

    func endAllowStream(for connection: NSXPCConnection) {
        storage.withLock { state in
            state.allowStreamClients.remove(ObjectIdentifier(connection))
        }
    }

    var allowStreamClientCount: Int {
        storage.withLock { $0.allowStreamClients.count }
    }

    // MARK: - Event broadcasting

    /// Appends the event to the history ring buffer and delivers it to registered clients.
    /// Deny events are delivered to all clients; allow events are delivered only to clients that have subscribed via beginAllowStream.
    func broadcast(_ event: FolderOpenEvent) {
        let (denyClients, allowClients) = storage.withLock { state -> ([NSXPCConnection], [NSXPCConnection]) in
            state.recentEvents.append(event)
            if state.recentEvents.count > maxHistoryCount {
                state.recentEvents.removeFirst(state.recentEvents.count - maxHistoryCount)
            }
            let allClients = Array(state.guiClients.values)
            guard event.accessAllowed else {
                return (allClients, [])
            }
            let subscribed = allClients.filter { state.allowStreamClients.contains(ObjectIdentifier($0)) }
            return ([], subscribed)
        }
        for conn in denyClients {
            (conn.remoteObjectProxy as? ClientProtocol)?.folderOpened(event)
        }
        for conn in allowClients {
            (conn.remoteObjectProxy as? ClientProtocol)?.folderOpened(event)
        }
    }

    func recentEvents() -> [FolderOpenEvent] {
        storage.withLock { $0.recentEvents }
    }

    func broadcast(_ event: TamperAttemptEvent) {
        let clients = storage.withLock { state -> [NSXPCConnection] in
            state.recentTamperEvents.append(event)
            if state.recentTamperEvents.count > maxHistoryCount {
                state.recentTamperEvents.removeFirst(state.recentTamperEvents.count - maxHistoryCount)
            }
            return Array(state.guiClients.values)
        }
        for conn in clients {
            (conn.remoteObjectProxy as? ClientProtocol)?.tamperAttemptDenied(event)
        }
    }

    func recentTamperEvents() -> [TamperAttemptEvent] {
        storage.withLock { $0.recentTamperEvents }
    }

    // MARK: - State broadcasting

    /// Calls `send` once for each currently-registered client.
    func broadcastToAllClients(_ send: (ClientProtocol) -> Void) {
        let clients = storage.withLock { Array($0.guiClients.values) }
        for conn in clients {
            guard let proxy = conn.remoteObjectProxy as? ClientProtocol else { continue }
            send(proxy)
        }
    }
}

// MARK: - AuthorizationBroadcasting

extension EventBroadcaster: AuthorizationBroadcasting {
    func requestAuthorizationFromFirstClient(
        processName: String,
        signingID: String,
        teamID: String,
        pid: Int,
        pidVersion: UInt32,
        path: String,
        isWrite: Bool,
        remainingSeconds: Double,
        ancestors: [AncestorInfo],
        reply: @escaping (Bool) -> Void
    ) {
        let connection: NSXPCConnection? = storage.withLock { $0.guiClients.values.first }
        guard let connection else {
            reply(false)
            return
        }
        let alreadyReplied = OSAllocatedUnfairLock(initialState: false)
        let safeReply: (Bool) -> Void = { allowed in
            let skip = alreadyReplied.withLock { replied -> Bool in
                if replied { return true }
                replied = true
                return false
            }
            guard !skip else { return }
            reply(allowed)
        }
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
            safeReply(false)
        } as? ClientProtocol
        guard let proxy else {
            safeReply(false)
            return
        }
        proxy.requestAuthorization(
            processName: processName,
            signingID: signingID,
            teamID: teamID,
            pid: pid,
            pidVersion: pidVersion,
            path: path,
            isWrite: isWrite,
            remainingSeconds: remainingSeconds,
            ancestors: ancestors,
            withReply: safeReply
        )
    }
}
