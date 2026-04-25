//
//  MetricsBroadcaster.swift
//  opfilter
//
//  Owns the subscription set for the metricsUpdated stream and drives the
//  1Hz sampling timer on subscriber-count transitions. Lives next to
//  EventBroadcaster but keeps metrics concerns isolated so neither type
//  accumulates responsibilities.
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "metrics-broadcaster")

final class MetricsBroadcaster: @unchecked Sendable {
    private struct State {
        var guiClients: [ObjectIdentifier: NSXPCConnection] = [:]
        var streamClients: Set<ObjectIdentifier> = []
        var timerRunning: Bool = false
    }

    private let storage: OSAllocatedUnfairLock<State>
    private let timerController: MetricsTimerControlling

    init(timerController: MetricsTimerControlling) {
        self.storage = OSAllocatedUnfairLock(initialState: State())
        self.timerController = timerController
    }

    @discardableResult
    func addClient(_ connection: NSXPCConnection) -> Int {
        storage.withLock { state in
            state.guiClients[ObjectIdentifier(connection)] = connection
            return state.guiClients.count
        }
    }

    @discardableResult
    func beginStream(for connection: NSXPCConnection) -> Bool {
        let shouldStart = storage.withLock { state -> Bool in
            let id = ObjectIdentifier(connection)
            let wasEmpty = state.streamClients.isEmpty
            state.streamClients.insert(id)
            if wasEmpty && !state.timerRunning {
                state.timerRunning = true
                return true
            }
            return false
        }
        if shouldStart { timerController.start() }
        return true
    }

    @discardableResult
    func endStream(for connection: NSXPCConnection) -> Bool {
        let shouldStop = storage.withLock { state -> Bool in
            state.streamClients.remove(ObjectIdentifier(connection))
            if state.streamClients.isEmpty && state.timerRunning {
                state.timerRunning = false
                return true
            }
            return false
        }
        if shouldStop { timerController.stop() }
        return true
    }
}
