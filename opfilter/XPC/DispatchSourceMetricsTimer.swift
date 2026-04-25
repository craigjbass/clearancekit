//
//  DispatchSourceMetricsTimer.swift
//  opfilter
//
//  Wraps a DispatchSource timer that fires once per second on the metrics
//  queue. Owns an isRunning flag so start()/stop() are idempotent.
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "metrics-timer")

final class DispatchSourceMetricsTimer: MetricsTimerControlling, @unchecked Sendable {
    private let timer: DispatchSourceTimer
    private let lock = OSAllocatedUnfairLock<Bool>(initialState: false)

    init(queue: DispatchQueue, sample: @escaping @Sendable () -> Void) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timer.setEventHandler(handler: sample)
        self.timer = timer
    }

    func start() {
        let shouldResume = lock.withLock { running -> Bool in
            guard !running else { return false }
            running = true
            return true
        }
        guard shouldResume else { return }
        timer.resume()
    }

    func stop() {
        let shouldSuspend = lock.withLock { running -> Bool in
            guard running else { return false }
            running = false
            return true
        }
        guard shouldSuspend else { return }
        timer.suspend()
    }
}
