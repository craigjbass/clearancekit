//
//  PipelineMetricsSnapshot.swift
//

import Foundation

@objc(PipelineMetricsSnapshot)
public final class PipelineMetricsSnapshot: NSObject, NSSecureCoding {
    public static let supportsSecureCoding = true

    public let eventBufferEnqueueCount: UInt64
    public let eventBufferDropCount: UInt64
    public let hotPathProcessedCount: UInt64
    public let hotPathRespondedCount: UInt64
    public let slowQueueEnqueueCount: UInt64
    public let slowQueueDropCount: UInt64
    public let slowPathProcessedCount: UInt64
    public let timestamp: Date

    public init(
        eventBufferEnqueueCount: UInt64,
        eventBufferDropCount: UInt64,
        hotPathProcessedCount: UInt64,
        hotPathRespondedCount: UInt64,
        slowQueueEnqueueCount: UInt64,
        slowQueueDropCount: UInt64,
        slowPathProcessedCount: UInt64,
        timestamp: Date = Date()
    ) {
        self.eventBufferEnqueueCount = eventBufferEnqueueCount
        self.eventBufferDropCount    = eventBufferDropCount
        self.hotPathProcessedCount   = hotPathProcessedCount
        self.hotPathRespondedCount   = hotPathRespondedCount
        self.slowQueueEnqueueCount   = slowQueueEnqueueCount
        self.slowQueueDropCount      = slowQueueDropCount
        self.slowPathProcessedCount  = slowPathProcessedCount
        self.timestamp               = timestamp
    }

    public required init?(coder: NSCoder) {
        eventBufferEnqueueCount = UInt64(bitPattern: coder.decodeInt64(forKey: "eventBufferEnqueueCount"))
        eventBufferDropCount    = UInt64(bitPattern: coder.decodeInt64(forKey: "eventBufferDropCount"))
        hotPathProcessedCount   = UInt64(bitPattern: coder.decodeInt64(forKey: "hotPathProcessedCount"))
        hotPathRespondedCount   = UInt64(bitPattern: coder.decodeInt64(forKey: "hotPathRespondedCount"))
        slowQueueEnqueueCount   = UInt64(bitPattern: coder.decodeInt64(forKey: "slowQueueEnqueueCount"))
        slowQueueDropCount      = UInt64(bitPattern: coder.decodeInt64(forKey: "slowQueueDropCount"))
        slowPathProcessedCount  = UInt64(bitPattern: coder.decodeInt64(forKey: "slowPathProcessedCount"))
        timestamp = (coder.decodeObject(of: NSDate.self, forKey: "timestamp") as Date?) ?? Date()
    }

    public func encode(with coder: NSCoder) {
        coder.encode(Int64(bitPattern: eventBufferEnqueueCount), forKey: "eventBufferEnqueueCount")
        coder.encode(Int64(bitPattern: eventBufferDropCount),    forKey: "eventBufferDropCount")
        coder.encode(Int64(bitPattern: hotPathProcessedCount),   forKey: "hotPathProcessedCount")
        coder.encode(Int64(bitPattern: hotPathRespondedCount),   forKey: "hotPathRespondedCount")
        coder.encode(Int64(bitPattern: slowQueueEnqueueCount),   forKey: "slowQueueEnqueueCount")
        coder.encode(Int64(bitPattern: slowQueueDropCount),      forKey: "slowQueueDropCount")
        coder.encode(Int64(bitPattern: slowPathProcessedCount),  forKey: "slowPathProcessedCount")
        coder.encode(timestamp as NSDate,                         forKey: "timestamp")
    }
}
