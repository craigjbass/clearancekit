//
//  FileAuthPipeline.swift
//  opfilter
//
//  2-stage pipeline for file-auth event processing:
//  Stage 1 (hot path): single serial consumer for cheap classifications
//  Stage 2 (slow path): bounded worker pool for ancestry-requiring decisions
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "pipeline")

// MARK: - SlowWorkItem

private struct SlowWorkItem: @unchecked Sendable {
    let fileEvent: FileAuthEvent
    let rules: [FAARule]
    let allowlist: [AllowlistEntry]
    let ancestorAllowlist: [AncestorAllowlistEntry]
}

// MARK: - FileAuthPipeline

final class FileAuthPipeline: @unchecked Sendable {
    private let eventBuffer: BoundedQueue<FileAuthEvent>
    private let slowQueue: BoundedQueue<SlowWorkItem>
    private let processTree: ProcessTreeProtocol
    private let rulesProvider: @Sendable () -> [FAARule]
    private let allowlistProvider: @Sendable () -> [AllowlistEntry]
    private let ancestorAllowlistProvider: @Sendable () -> [AncestorAllowlistEntry]
    private let postRespondHandler: @Sendable (FileAuthEvent, PolicyDecision, [AncestorInfo], UInt64) -> Void
    private let hotPathQueue: DispatchQueue
    private let slowWorkerQueue: DispatchQueue
    private let slowWorkerSemaphore: DispatchSemaphore
    private let eventSignal: DispatchSemaphore
    private let slowSignal: DispatchSemaphore
    private let metricsStorage: OSAllocatedUnfairLock<PipelineMetrics>

    init(
        processTree: ProcessTreeProtocol,
        rulesProvider: @escaping @Sendable () -> [FAARule],
        allowlistProvider: @escaping @Sendable () -> [AllowlistEntry],
        ancestorAllowlistProvider: @escaping @Sendable () -> [AncestorAllowlistEntry],
        postRespond: @escaping @Sendable (FileAuthEvent, PolicyDecision, [AncestorInfo], UInt64) -> Void,
        eventBufferCapacity: Int = 1024,
        slowQueueCapacity: Int = 256,
        hotPathQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.hot", qos: .userInteractive),
        slowWorkerQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.slow", qos: .userInitiated, attributes: .concurrent),
        slowWorkerSemaphore: DispatchSemaphore = DispatchSemaphore(value: 2),
        eventSignal: DispatchSemaphore = DispatchSemaphore(value: 0),
        slowSignal: DispatchSemaphore = DispatchSemaphore(value: 0)
    ) {
        self.eventBuffer = BoundedQueue(capacity: eventBufferCapacity)
        self.slowQueue = BoundedQueue(capacity: slowQueueCapacity)
        self.processTree = processTree
        self.rulesProvider = rulesProvider
        self.allowlistProvider = allowlistProvider
        self.ancestorAllowlistProvider = ancestorAllowlistProvider
        self.postRespondHandler = postRespond
        self.hotPathQueue = hotPathQueue
        self.slowWorkerQueue = slowWorkerQueue
        self.slowWorkerSemaphore = slowWorkerSemaphore
        self.eventSignal = eventSignal
        self.slowSignal = slowSignal
        self.metricsStorage = OSAllocatedUnfairLock(initialState: PipelineMetrics())
    }

    // MARK: - Lifecycle

    func start() {
        hotPathQueue.async { [weak self] in
            self?.hotPathLoop()
        }
        slowWorkerQueue.async { [weak self] in
            self?.slowDispatchLoop()
        }
    }

    // MARK: - Submit

    func submit(_ event: FileAuthEvent) {
        let result = eventBuffer.tryEnqueue(event)
        switch result {
        case .enqueued:
            metricsStorage.withLock { $0.eventBufferEnqueueCount += 1 }
            eventSignal.signal()
        case .full:
            metricsStorage.withLock { $0.eventBufferDropCount += 1 }
            logger.warning("PIPELINE-DROP cid=\(event.correlationID) pid=\(event.processID) path=\(event.path, privacy: .public) ttdMs=\(MachTime.millisecondsToDeadline(event.deadline))")
            event.respond(true, false)
            let ancestors = processTree.ancestors(of: event.processIdentity)
            postRespondHandler(event, .noRuleApplies, ancestors, 0)
        }
    }

    // MARK: - Metrics

    func metrics() -> PipelineMetrics {
        metricsStorage.withLock { $0 }
    }

    // MARK: - Hot path

    private func hotPathLoop() {
        while true {
            eventSignal.wait()
            guard let event = eventBuffer.dequeue() else { continue }
            processHotPath(event)
        }
    }

    private func processHotPath(_ event: FileAuthEvent) {
        metricsStorage.withLock { $0.hotPathProcessedCount += 1 }

        let allowlist = allowlistProvider()
        let ancestorAllowlist = ancestorAllowlistProvider()

        if isGloballyAllowed(allowlist: allowlist, processPath: event.processPath, signingID: event.signingID, teamID: event.teamID) {
            event.respond(true, true)
            metricsStorage.withLock { $0.hotPathRespondedCount += 1 }
            let ancestors = processTree.ancestors(of: event.processIdentity)
            postRespondHandler(event, .globallyAllowed, ancestors, 0)
            return
        }

        let rules = rulesProvider()
        let classification = classifyPaths(event.path, secondaryPath: event.secondaryPath, rules: rules)

        switch classification {
        case .noRuleApplies:
            event.respond(true, true)
            metricsStorage.withLock { $0.hotPathRespondedCount += 1 }
            let ancestors = processTree.ancestors(of: event.processIdentity)
            postRespondHandler(event, .noRuleApplies, ancestors, 0)

        case .processLevelOnly where ancestorAllowlist.isEmpty:
            let decision = evaluateAccess(
                rules: rules, allowlist: allowlist, ancestorAllowlist: [],
                path: event.path, secondaryPath: event.secondaryPath, processPath: event.processPath,
                teamID: event.teamID, signingID: event.signingID,
                ancestors: []
            )
            event.respond(decision.isAllowed, false)
            metricsStorage.withLock { $0.hotPathRespondedCount += 1 }
            let ancestors = processTree.ancestors(of: event.processIdentity)
            postRespondHandler(event, decision, ancestors, 0)

        case .processLevelOnly, .ancestryRequired:
            let workItem = SlowWorkItem(
                fileEvent: event,
                rules: rules,
                allowlist: allowlist,
                ancestorAllowlist: ancestorAllowlist
            )
            let enqueueResult = slowQueue.tryEnqueue(workItem)
            switch enqueueResult {
            case .enqueued:
                metricsStorage.withLock { $0.slowQueueEnqueueCount += 1 }
                slowSignal.signal()
            case .full:
                metricsStorage.withLock { $0.slowQueueDropCount += 1 }
                logger.warning("SLOW-DROP cid=\(event.correlationID) pid=\(event.processID) path=\(event.path, privacy: .public) ttdMs=\(MachTime.millisecondsToDeadline(event.deadline))")
                event.respond(true, false)
                metricsStorage.withLock { $0.hotPathRespondedCount += 1 }
                let ancestors = processTree.ancestors(of: event.processIdentity)
                postRespondHandler(event, .noRuleApplies, ancestors, 0)
            }
        }
    }

    // MARK: - Slow path

    private func slowDispatchLoop() {
        while true {
            slowSignal.wait()
            slowWorkerSemaphore.wait()
            guard let workItem = slowQueue.dequeue() else {
                slowWorkerSemaphore.signal()
                continue
            }
            slowWorkerQueue.async { [weak self] in
                self?.processSlowPath(workItem)
                self?.slowWorkerSemaphore.signal()
            }
        }
    }

    private func processSlowPath(_ workItem: SlowWorkItem) {
        metricsStorage.withLock { $0.slowPathProcessedCount += 1 }

        let event = workItem.fileEvent
        let dwellNanoseconds = waitForProcess(event.processIdentity, deadline: event.deadline)

        let ancestors = processTree.ancestors(of: event.processIdentity)
        let decision = evaluateAccess(
            rules: workItem.rules,
            allowlist: workItem.allowlist,
            ancestorAllowlist: workItem.ancestorAllowlist,
            path: event.path,
            secondaryPath: event.secondaryPath,
            processPath: event.processPath,
            teamID: event.teamID,
            signingID: event.signingID,
            ancestors: ancestors
        )

        event.respond(decision.isAllowed, false)

        let logAncestors = processTree.ancestors(of: event.processIdentity)
        postRespondHandler(event, decision, logAncestors, dwellNanoseconds)
    }

    private func waitForProcess(_ identity: ProcessIdentity, deadline: UInt64) -> UInt64 {
        let start = mach_absolute_time()
        let cutoff = MachTime.cutoff(for: deadline)
        while mach_absolute_time() < cutoff {
            guard !processTree.contains(identity: identity) else { break }
            Thread.sleep(forTimeInterval: 0.001)
        }
        return MachTime.nanoseconds(from: start, to: mach_absolute_time())
    }
}
