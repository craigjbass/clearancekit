//
//  main.swift
//  opfilter
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation
import OSLog

let evictionQueue      = DispatchQueue(label: "uk.craigbass.clearancekit.process-tree-eviction", qos: .background)
let esAdapterQueue     = DispatchQueue(label: "uk.craigbass.clearancekit.es-adapter",            qos: .userInteractive)
let esJailAdapterQueue = DispatchQueue(label: "uk.craigbass.clearancekit.es-jail-adapter",       qos: .userInteractive)
let hotPathQueue       = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.hot",          qos: .userInteractive)
let slowWorkerQueue    = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.slow",         qos: .userInitiated,    attributes: .concurrent)
let processTreeQueue   = DispatchQueue(label: "uk.craigbass.clearancekit.process-tree",          qos: .userInitiated)
let postRespondQueue   = DispatchQueue(label: "uk.craigbass.clearancekit.post-respond",          qos: .background)
let xpcServerQueue     = DispatchQueue(label: "uk.craigbass.clearancekit.xpc-server",            qos: .userInitiated)
let metricsQueue       = DispatchQueue(label: "uk.craigbass.clearancekit.metrics",               qos: .utility)
let jailSweepQueue     = DispatchQueue(label: "uk.craigbass.clearancekit.jail-sweep",            qos: .background)
let jailCascadeQueue   = DispatchQueue(label: "uk.craigbass.clearancekit.jail-cascade",          qos: .background,       attributes: .concurrent)

let slowWorkerSemaphore = DispatchSemaphore(value: 2)
let eventSignal = DispatchSemaphore(value: 0)
let slowSignal = DispatchSemaphore(value: 0)

let dataDirectory = URL(fileURLWithPath: "/Library/Application Support/clearancekit")

// Start the XPC server before the slow process-tree scan so the GUI can connect
// immediately and show a loading state while opfilter finishes initialising.
let broadcaster = EventBroadcaster()
let server = XPCServer(broadcaster: broadcaster, serverQueue: xpcServerQueue)
server.start()

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

let postRespondHandler = PostRespondHandler(postRespondQueue: postRespondQueue)
let allowlistState = AllowlistState()
let authorizationGate = AuthorizationGate()

let bundleCodesignCache = BundleCodesignCache()
let bundleProtectionEvaluator = BundleProtectionEvaluator(
    cache: bundleCodesignCache,
    updaterSignaturesProvider: { policyRepository.bundleUpdaterSignatures() }
)

let faaInteractorRef = WeakBox<FAAFilterInteractor>()
let pipeline = FileAuthPipeline(
    processTree: processTree,
    rulesProvider: { faaInteractorRef.value?.currentRules() ?? [] },
    allowlistProvider: { allowlistState.currentAllowlist() },
    ancestorAllowlistProvider: { allowlistState.currentAncestorAllowlist() },
    postRespond: { event, decision, ancestors, dwell in
        postRespondHandler.postRespond(fileEvent: event, decision: decision, ancestors: ancestors, dwellNanoseconds: dwell)
        if event.path.contains("/_CodeSignature/"),
           let bundlePath = BundlePath.extract(from: event.path) {
            bundleCodesignCache.invalidate(bundlePath: bundlePath)
        }
    },
    authorizationGate: authorizationGate,
    authorizationHandler: { event, duration, rulePrefix, ancestors in
        authorizationGate.requestAuthorization(
            event: event,
            rulePrefix: rulePrefix,
            ancestors: ancestors,
            sessionDuration: duration,
            broadcaster: broadcaster,
            postRespond: { evt, decision, ancestors, dwell in
                postRespondHandler.postRespond(fileEvent: evt, decision: decision, ancestors: ancestors, dwellNanoseconds: dwell)
            }
        )
    },
    hotPathQueue: hotPathQueue,
    slowWorkerQueue: slowWorkerQueue,
    slowWorkerSemaphore: slowWorkerSemaphore,
    eventSignal: eventSignal,
    slowSignal: slowSignal,
    bundleProtectionEvaluator: bundleProtectionEvaluator
)
let faaInteractor = FAAFilterInteractor(
    initialRules: faaPolicy,
    allowlistState: allowlistState,
    processTree: processTree,
    pipeline: pipeline,
    processTreeQueue: processTreeQueue,
    postRespondHandler: postRespondHandler
)
faaInteractorRef.value = faaInteractor
pipeline.start()

let jailInteractor = JailFilterInteractor(
    allowlistState: allowlistState,
    processTree: processTree,
    postRespondHandler: postRespondHandler
)

let tamperResistanceAdapter = ESTamperResistanceAdapter(esAPI: LiveEndpointSecurityAPI())

let adapter = ESInboundAdapter(interactor: faaInteractor, esAdapterQueue: esAdapterQueue)
let jailAdapter = ESJailAdapter(interactor: jailInteractor, processTree: processTree, esJailAdapterQueue: esJailAdapterQueue, jailSweepQueue: jailSweepQueue, jailCascadeQueue: jailCascadeQueue)

server.configure(XPCServer.ServerContext(
    processTree: processTree,
    policyRepository: policyRepository,
    faaInteractor: faaInteractor,
    jailInteractor: jailInteractor,
    adapter: adapter,
    jailAdapter: jailAdapter
))

postRespondHandler.onEvent = { event in
    server.handleEvent(event)
}

tamperResistanceAdapter.onTamperDenied = { event in server.handleTamperEvent(event) }
tamperResistanceAdapter.start()

let initialRules = server.mergedRules()
server.startJailAdapterIfEnabled()
jailAdapter.startSweepTimer()
adapter.start(initialRules: initialRules, onXProtectChanged: { server.handleXProtectChange() })
server.applyPolicyToFilter()
server.applyAllowlistToFilter()
server.applyJailRulesToFilter()

let metricsLogger = Logger(subsystem: "uk.craigbass.clearancekit.metrics", category: "metrics")
let metricsTimer = DispatchSource.makeTimerSource(queue: metricsQueue)
metricsTimer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
metricsTimer.setEventHandler {
    let sampleDate = Date(timeIntervalSince1970: Double(clock_gettime_nsec_np(CLOCK_REALTIME)) / 1_000_000_000)
    let m = pipeline.metrics()
    let jm = jailInteractor.jailMetrics()
    server.pushMetrics(m, jail: jm, timestamp: sampleDate)
    metricsLogger.info("""
    pipeline_metrics \
    ts=\(sampleDate.timeIntervalSince1970, privacy: .public) \
    eventBufferEnqueueCount=\(m.eventBufferEnqueueCount, privacy: .public) \
    eventBufferDropCount=\(m.eventBufferDropCount, privacy: .public) \
    hotPathProcessedCount=\(m.hotPathProcessedCount, privacy: .public) \
    hotPathRespondedCount=\(m.hotPathRespondedCount, privacy: .public) \
    slowQueueEnqueueCount=\(m.slowQueueEnqueueCount, privacy: .public) \
    slowQueueDropCount=\(m.slowQueueDropCount, privacy: .public) \
    slowPathProcessedCount=\(m.slowPathProcessedCount, privacy: .public) \
    jailEvaluatedCount=\(jm.jailEvaluatedCount, privacy: .public) \
    jailDenyCount=\(jm.jailDenyCount, privacy: .public)
    """)
}
metricsTimer.resume()

dispatchMain()
