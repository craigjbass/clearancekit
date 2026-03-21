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
        var recentEvents: [FolderOpenEvent] = []
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
            state.guiClients.removeValue(forKey: ObjectIdentifier(connection))
            return state.guiClients.count
        }
    }

    // MARK: - Event broadcasting

    /// Appends the event to the history ring buffer and delivers it to all registered clients.
    func broadcast(_ event: FolderOpenEvent) {
        let clients = storage.withLock { state -> [NSXPCConnection] in
            state.recentEvents.append(event)
            if state.recentEvents.count > maxHistoryCount {
                state.recentEvents.removeFirst(state.recentEvents.count - maxHistoryCount)
            }
            return Array(state.guiClients.values)
        }
        for conn in clients {
            (conn.remoteObjectProxy as? ClientProtocol)?.folderOpened(event)
        }
    }

    func recentEvents() -> [FolderOpenEvent] {
        storage.withLock { $0.recentEvents }
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
