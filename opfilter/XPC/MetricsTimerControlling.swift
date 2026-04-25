//
//  MetricsTimerControlling.swift
//  opfilter
//

import Foundation

/// Drives the 1Hz pipeline-metrics sampling timer. Implementations must be idempotent:
/// `start()` while running is a no-op, `stop()` while stopped is a no-op.
protocol MetricsTimerControlling: AnyObject, Sendable {
    func start()
    func stop()
}
