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
}
