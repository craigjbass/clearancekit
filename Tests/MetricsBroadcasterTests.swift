//
//  MetricsBroadcasterTests.swift
//  clearancekitTests
//

import Testing
import Foundation
import os

@Suite("MetricsBroadcaster")
struct MetricsBroadcasterTests {

    private final class FakeMetricsTimer: MetricsTimerControlling, @unchecked Sendable {
        private let lock = OSAllocatedUnfairLock<(starts: Int, stops: Int)>(initialState: (0, 0))
        var startCount: Int { lock.withLock { $0.starts } }
        var stopCount: Int { lock.withLock { $0.stops } }
        func start() { lock.withLock { $0.starts += 1 } }
        func stop()  { lock.withLock { $0.stops += 1 } }
    }

    @Test("first subscriber starts the timer")
    func firstSubscriberStartsTimer() {
        let timer = FakeMetricsTimer()
        let broadcaster = MetricsBroadcaster(timerController: timer)
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)

        broadcaster.beginStream(for: conn)

        #expect(timer.startCount == 1)
        #expect(timer.stopCount == 0)
    }

    @Test("second subscriber does not restart the timer")
    func secondSubscriberDoesNotRestartTimer() {
        let timer = FakeMetricsTimer()
        let broadcaster = MetricsBroadcaster(timerController: timer)
        let connA = NSXPCConnection()
        let connB = NSXPCConnection()
        broadcaster.addClient(connA)
        broadcaster.addClient(connB)

        broadcaster.beginStream(for: connA)
        broadcaster.beginStream(for: connB)

        #expect(timer.startCount == 1)
    }
}
