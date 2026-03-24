//
//  main.swift
//  opfilter
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation
import OSLog

let evictionQueue = DispatchQueue(label: "uk.craigbass.clearancekit.process-tree-eviction", qos: .background)
let hotPathQueue = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.hot", qos: .userInteractive)
let slowWorkerQueue = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.slow", qos: .userInitiated, attributes: .concurrent)
let slowWorkerSemaphore = DispatchSemaphore(value: 2)
let eventSignal = DispatchSemaphore(value: 0)
let slowSignal = DispatchSemaphore(value: 0)
let postRespondQueue = DispatchQueue(label: "uk.craigbass.clearancekit.post-respond", qos: .background)
let xpcServerQueue = DispatchQueue(label: "uk.craigbass.clearancekit.xpc-server", qos: .userInitiated)

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
    postRespondQueue: postRespondQueue
)
interactorRef.value = interactor
pipeline.start()

let adapter = ESInboundAdapter(interactor: interactor)
let jailAdapter = ESJailAdapter(interactor: interactor)
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
let metricsQueue = DispatchQueue(label: "uk.craigbass.clearancekit.metrics", qos: .utility)
let timer = DispatchSource.makeTimerSource(queue: metricsQueue)

timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))

timer.setEventHandler {
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

timer.resume()

dispatchMain()
