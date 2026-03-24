//
//  PipelineMetrics.swift
//  opfilter
//

struct PipelineMetrics: Sendable {
    var eventBufferEnqueueCount: UInt64 = 0
    var eventBufferDropCount: UInt64 = 0
    var hotPathProcessedCount: UInt64 = 0
    var hotPathRespondedCount: UInt64 = 0
    var slowQueueEnqueueCount: UInt64 = 0
    var slowQueueDropCount: UInt64 = 0
    var slowPathProcessedCount: UInt64 = 0
}
