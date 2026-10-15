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
    private let authorizationGate: AuthorizationGate
    private let authorizationHandler: @Sendable (FileAuthEvent, TimeInterval, String, AuthorizationSubject) -> Void
    private let hotPathQueue: DispatchQueue
    private let slowWorkerQueue: DispatchQueue
    private let slowWorkerSemaphore: DispatchSemaphore
    private let eventSignal: DispatchSemaphore
    private let slowSignal: DispatchSemaphore
    private let metricsStorage: OSAllocatedUnfairLock<PipelineMetrics>
    private let bundleProtectionEvaluator: BundleProtectionEvaluator?

    init(
        processTree: ProcessTreeProtocol,
        rulesProvider: @escaping @Sendable () -> [FAARule],
        allowlistProvider: @escaping @Sendable () -> [AllowlistEntry],
        ancestorAllowlistProvider: @escaping @Sendable () -> [AncestorAllowlistEntry],
        postRespond: @escaping @Sendable (FileAuthEvent, PolicyDecision, [AncestorInfo], UInt64) -> Void,
        authorizationGate: AuthorizationGate = AuthorizationGate(),
        authorizationHandler: @escaping @Sendable (FileAuthEvent, TimeInterval, String, AuthorizationSubject) -> Void = { _, _, _, _ in },
        eventBufferCapacity: Int = 1024,
        slowQueueCapacity: Int = 256,
        hotPathQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.hot", qos: .userInteractive),
        slowWorkerQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.slow", qos: .userInitiated, attributes: .concurrent),
        slowWorkerSemaphore: DispatchSemaphore = DispatchSemaphore(value: 2),
        eventSignal: DispatchSemaphore = DispatchSemaphore(value: 0),
        slowSignal: DispatchSemaphore = DispatchSemaphore(value: 0),
        bundleProtectionEvaluator: BundleProtectionEvaluator? = nil
    ) {
        self.eventBuffer = BoundedQueue(capacity: eventBufferCapacity)
        self.slowQueue = BoundedQueue(capacity: slowQueueCapacity)
        self.processTree = processTree
        self.rulesProvider = rulesProvider
        self.allowlistProvider = allowlistProvider
        self.ancestorAllowlistProvider = ancestorAllowlistProvider
        self.postRespondHandler = postRespond
        self.authorizationGate = authorizationGate
        self.authorizationHandler = authorizationHandler
        self.hotPathQueue = hotPathQueue
        self.slowWorkerQueue = slowWorkerQueue
        self.slowWorkerSemaphore = slowWorkerSemaphore
        self.eventSignal = eventSignal
        self.slowSignal = slowSignal
        self.metricsStorage = OSAllocatedUnfairLock(initialState: PipelineMetrics())
        self.bundleProtectionEvaluator = bundleProtectionEvaluator
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
        let rules = rulesProvider()

        if isGloballyAllowed(allowlist: allowlist, processPath: event.processPath, signingID: event.signingID, teamID: event.teamID) {
            event.respond(true, allowIsCacheable(for: event, rules: rules))
            metricsStorage.withLock { $0.hotPathRespondedCount += 1 }
            let ancestors = processTree.ancestors(of: event.processIdentity)
            postRespondHandler(event, .globallyAllowed, ancestors, 0)
            return
        }

        if let evaluator = bundleProtectionEvaluator,
           evaluator.isBundleWrite(path: event.path, accessKind: event.accessKind) {
            let workItem = SlowWorkItem(
                fileEvent: event,
                rules: rules,
                allowlist: allowlist,
                ancestorAllowlist: ancestorAllowlist
            )
            switch slowQueue.tryEnqueue(workItem) {
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
            return
        }

        let classification = classifyPaths(event.path, secondaryPath: event.secondaryPath, reach: event.reach, rules: rules)

        switch classification {
        case .noRuleApplies:
            event.respond(true, allowIsCacheable(for: event, rules: rules))
            metricsStorage.withLock { $0.hotPathRespondedCount += 1 }
            let ancestors = processTree.ancestors(of: event.processIdentity)
            postRespondHandler(event, .noRuleApplies, ancestors, 0)

        case .processLevelOnly where ancestorAllowlist.isEmpty:
            let responsibleRecord = responsibleRecord(of: event)
            let decision = evaluateAccess(
                rules: rules, allowlist: allowlist, ancestorAllowlist: [],
                path: event.path, secondaryPath: event.secondaryPath, reach: event.reach,
                subject: policySubject(for: event, ancestors: [], responsibleRecord: responsibleRecord, responsibleAncestors: []),
                accessKind: event.accessKind
            )
            let hotAncestors = processTree.ancestors(of: event.processIdentity)
            if handleDecisionWithAuthorization(decision, event: event, ancestors: hotAncestors, dwellNanoseconds: 0) {
                metricsStorage.withLock { $0.hotPathRespondedCount += 1 }
                return
            }
            event.respond(decision.isAllowed, false)
            metricsStorage.withLock { $0.hotPathRespondedCount += 1 }
            postRespondHandler(event, decision, hotAncestors, 0)

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
        let responsibleRecord = responsibleRecord(of: event)

        let faaDecision = evaluateAccess(
            rules: workItem.rules,
            allowlist: workItem.allowlist,
            ancestorAllowlist: workItem.ancestorAllowlist,
            path: event.path,
            secondaryPath: event.secondaryPath,
            reach: event.reach,
            subject: policySubject(
                for: event,
                ancestors: ancestors,
                responsibleRecord: responsibleRecord,
                responsibleAncestors: responsibleAncestors(of: responsibleRecord)
            ),
            accessKind: event.accessKind
        )
        let decision = combinedDecision(
            bundleDecision: bundleProtectionDecision(for: event, ancestors: ancestors),
            faaDecision: faaDecision
        )

        let logAncestors = processTree.ancestors(of: event.processIdentity)
        if handleDecisionWithAuthorization(decision, event: event, ancestors: logAncestors, dwellNanoseconds: dwellNanoseconds) {
            return
        }
        event.respond(decision.isAllowed, false)
        postRespondHandler(event, decision, logAncestors, dwellNanoseconds)
    }

    // ES caches an allow per executable file and target file, and every
    // WebKit Networking process shares one executable. A cached allow given to
    // one service process would also skip the rule check for the next one,
    // whose responsible process can be a different app.
    private func allowIsCacheable(for event: FileAuthEvent, rules: [FAARule]) -> Bool {
        guard event.cachesAllowResponse else { return false }
        return !anyRuleChecksResponsibleProcess(of: event, rules: rules)
    }

    private func anyRuleChecksResponsibleProcess(of event: FileAuthEvent, rules: [FAARule]) -> Bool {
        let process = processFacts(of: event)
        return rules.contains { $0.checksResponsibleProcess(of: process) }
    }

    private func processFacts(of event: FileAuthEvent) -> ProcessFacts {
        ProcessFacts(processPath: event.processPath, teamID: event.teamID, signingID: event.signingID)
    }

    private func responsibleRecord(of event: FileAuthEvent) -> ProcessRecord? {
        guard event.responsibleIdentity != event.processIdentity else { return nil }
        guard let record = processTree.record(of: event.responsibleIdentity) else { return nil }
        guard record.identity != event.processIdentity else { return nil }
        return record
    }

    private func responsibleAncestors(of responsibleRecord: ProcessRecord?) -> [AncestorInfo] {
        guard let responsibleRecord else { return [] }
        return processTree.ancestors(of: responsibleRecord.identity)
    }

    private func policySubject(
        for event: FileAuthEvent,
        ancestors: [AncestorInfo],
        responsibleRecord: ProcessRecord?,
        responsibleAncestors: [AncestorInfo]
    ) -> PolicySubject {
        PolicySubject(
            process: processFacts(of: event),
            ancestors: ancestors,
            responsibleProcess: responsibleProcess(from: responsibleRecord),
            responsibleAncestors: responsibleAncestors
        )
    }

    private func responsibleProcess(from responsibleRecord: ProcessRecord?) -> ResponsibleProcess {
        guard let responsibleRecord else { return .unknown }
        return .known(ProcessFacts(
            processPath: responsibleRecord.path,
            teamID: responsibleRecord.teamID,
            signingID: responsibleRecord.signingID
        ))
    }

    private func bundleProtectionDecision(for event: FileAuthEvent, ancestors: [AncestorInfo]) -> PolicyDecision? {
        bundleProtectionEvaluator?.evaluate(
            accessPath: event.path,
            processTeamID: event.teamID,
            processSigningID: event.signingID,
            processUID: event.uid,
            accessKind: event.accessKind,
            ancestors: ancestors
        )
    }

    // The bundle decision is the first argument so that it names the matched
    // criterion in the audit log when both decisions allow.
    private func combinedDecision(bundleDecision: PolicyDecision?, faaDecision: PolicyDecision) -> PolicyDecision {
        guard let bundleDecision else { return faaDecision }
        return moreRestrictiveDecision(bundleDecision, faaDecision)
    }

    /// Returns true if the decision was handled as an authorization case (either
    /// via an active session allow or by handing off to the authorization handler).
    /// Returns false if the caller should proceed with normal respond/postRespond logic.
    private func handleDecisionWithAuthorization(
        _ decision: PolicyDecision,
        event: FileAuthEvent,
        ancestors: [AncestorInfo],
        dwellNanoseconds: UInt64
    ) -> Bool {
        guard case .requiresAuthorization(let ruleID, let ruleName, let ruleSource, _, let duration, let identifiedProcess) = decision else {
            return false
        }
        let subject = authorizationSubject(for: identifiedProcess, event: event, ancestors: ancestors)
        if authorizationGate.hasActiveSession(
            teamID: subject.teamID,
            signingID: subject.signingID,
            parentPID: subject.sessionOwnerIdentity.pid,
            parentPIDVersion: subject.sessionOwnerIdentity.pidVersion,
            ancestors: subject.ancestors,
            prefix: ruleName
        ) {
            authorizationGate.touchSession(
                teamID: subject.teamID,
                signingID: subject.signingID,
                parentPID: subject.sessionOwnerIdentity.pid,
                parentPIDVersion: subject.sessionOwnerIdentity.pidVersion,
                ancestors: subject.ancestors,
                prefix: ruleName
            )
            let sessionDecision = PolicyDecision.allowed(
                ruleID: ruleID,
                ruleName: ruleName,
                ruleSource: ruleSource,
                matchedCriterion: "authorized session",
                checkedProcess: identifiedProcess.checkedProcess
            )
            event.respond(true, false)
            postRespondHandler(event, sessionDecision, ancestors, dwellNanoseconds)
            return true
        }
        authorizationHandler(event, duration, ruleName, subject)
        return true
    }

    private func authorizationSubject(
        for identifiedProcess: IdentifiedProcess,
        event: FileAuthEvent,
        ancestors: [AncestorInfo]
    ) -> AuthorizationSubject {
        switch identifiedProcess {
        case .itself:
            return AuthorizationSubject(
                checkedProcess: identifiedProcess.checkedProcess,
                processPath: event.processPath,
                teamID: event.teamID,
                signingID: event.signingID,
                processIdentity: event.processIdentity,
                sessionOwnerIdentity: ProcessIdentity(pid: event.parentPID, pidVersion: event.parentPIDVersion),
                ancestors: ancestors
            )
        case .responsible(let facts):
            return AuthorizationSubject(
                checkedProcess: identifiedProcess.checkedProcess,
                processPath: facts.processPath,
                teamID: facts.teamID,
                signingID: facts.signingID,
                processIdentity: event.responsibleIdentity,
                sessionOwnerIdentity: event.responsibleIdentity,
                ancestors: processTree.ancestors(of: event.responsibleIdentity)
            )
        }
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
