//
//  main.swift
//  opfilter
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation
import OSLog

let evictionQueue    = DispatchQueue(label: "uk.craigbass.clearancekit.process-tree-eviction", qos: .background,       autoreleaseFrequency: .never)
let esAdapterQueue      = DispatchQueue(label: "uk.craigbass.clearancekit.es-adapter",       qos: .userInteractive,  autoreleaseFrequency: .never)
let esJailAdapterQueue  = DispatchQueue(label: "uk.craigbass.clearancekit.es-jail-adapter", qos: .userInteractive,  autoreleaseFrequency: .never)
let hotPathQueue     = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.hot",          qos: .userInteractive,  autoreleaseFrequency: .never)
let slowWorkerQueue  = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.slow",         qos: .userInitiated,    attributes: .concurrent, autoreleaseFrequency: .never)
let processTreeQueue = DispatchQueue(label: "uk.craigbass.clearancekit.process-tree",          qos: .userInitiated,    autoreleaseFrequency: .never)
let postRespondQueue = DispatchQueue(label: "uk.craigbass.clearancekit.post-respond",          qos: .background,       autoreleaseFrequency: .never)
let xpcServerQueue   = DispatchQueue(label: "uk.craigbass.clearancekit.xpc-server",            qos: .userInitiated,    autoreleaseFrequency: .never)
let metricsQueue     = DispatchQueue(label: "uk.craigbass.clearancekit.metrics",               qos: .utility,          autoreleaseFrequency: .never)
let cleanupQueue     = DispatchQueue(label: "uk.craigbass.clearancekit.cleanup",               qos: .background,       autoreleaseFrequency: .never)

let slowWorkerSemaphore = DispatchSemaphore(value: 2)
let eventSignal = DispatchSemaphore(value: 0)
let slowSignal = DispatchSemaphore(value: 0)

let dataDirectory = URL(fileURLWithPath: "/Library/Application Support/clearancekit")

let processTree = ProcessTree(evictionQueue: evictionQueue)
processTree.buildInitialTree()

let database = Database(directory: dataDirectory)
let managedRules = ManagedPolicyLoader.load()
let managedAllowlist = ManagedAllowlistLoader.load()
let managedJailRules = ManagedJailRuleLoader.load()
let xprotectEntries = enumerateXProtectEntries()
let policyRepository = PolicyRepository(
    database: database,
    managedRules: managedRules,
    managedAllowlist: managedAllowlist,
    managedJailRules: managedJailRules,
    xprotectEntries: xprotectEntries
)
let broadcaster = EventBroadcaster()

let interactorRef = WeakBox<FilterInteractor>()
let pipeline = FileAuthPipeline(
    processTree: processTree,
    rulesProvider: { interactorRef.value?.currentRules() ?? [] },
    allowlistProvider: { interactorRef.value?.currentAllowlist() ?? [] },
    ancestorAllowlistProvider: { interactorRef.value?.currentAncestorAllowlist() ?? [] },
    postRespond: { event, decision, ancestors, dwell in
        interactorRef.value?.postRespond(fileEvent: event, decision: decision, ancestors: ancestors, dwellNanoseconds: dwell)
    },
    hotPathQueue: hotPathQueue,
    slowWorkerQueue: slowWorkerQueue,
    slowWorkerSemaphore: slowWorkerSemaphore,
    eventSignal: eventSignal,
    slowSignal: slowSignal
)
let interactor = FilterInteractor(
    initialRules: faaPolicy,
    processTree: processTree,
    pipeline: pipeline,
    processTreeQueue: processTreeQueue,
    postRespondQueue: postRespondQueue
)
interactorRef.value = interactor
pipeline.start()

let adapter = ESInboundAdapter(interactor: interactor, esAdapterQueue: esAdapterQueue)
let jailAdapter = ESJailAdapter(interactor: interactor, esJailAdapterQueue: esJailAdapterQueue)
let server = XPCServer(
    policyRepository: policyRepository,
    broadcaster: broadcaster,
    interactor: interactor,
    adapter: adapter,
    jailAdapter: jailAdapter,
    serverQueue: xpcServerQueue
)

server.applyPolicyToFilter()
server.applyAllowlistToFilter()
server.applyJailRulesToFilter()

interactor.onEvent = { event in
    server.handleEvent(event)
}

server.start()

let initialRules = server.mergedRules()
server.startJailAdapterIfEnabled()
adapter.start(initialRules: initialRules, onXProtectChanged: { server.handleXProtectChange() })

let metricsLogger = Logger(subsystem: "uk.craigbass.clearancekit.metrics", category: "metrics")
let metricsTimer = DispatchSource.makeTimerSource(queue: metricsQueue)
metricsTimer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
metricsTimer.setEventHandler {
    let m = pipeline.metrics()
    metricsLogger.info("""
    pipeline_metrics \
    eventBufferEnqueueCount=\(m.eventBufferEnqueueCount, privacy: .public) \
    eventBufferDropCount=\(m.eventBufferDropCount, privacy: .public) \
    hotPathProcessedCount=\(m.hotPathProcessedCount, privacy: .public) \
    hotPathRespondedCount=\(m.hotPathRespondedCount, privacy: .public) \
    slowQueueEnqueueCount=\(m.slowQueueEnqueueCount, privacy: .public) \
    slowQueueDropCount=\(m.slowQueueDropCount, privacy: .public) \
    slowPathProcessedCount=\(m.slowPathProcessedCount, privacy: .public)
    """)
}
metricsTimer.resume()

let cleanupTimer = DispatchSource.makeTimerSource(queue: cleanupQueue)
cleanupTimer.schedule(deadline: .now() + .seconds(60), repeating: .seconds(60))
cleanupTimer.setEventHandler {
    autoreleasepool {}
}
cleanupTimer.resume()

dispatchMain()
