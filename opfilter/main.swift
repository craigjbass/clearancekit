//
//  main.swift
//  opfilter
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation

let evictionQueue = DispatchQueue(label: "uk.craigbass.clearancekit.process-tree-eviction")
let hotPathQueue = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.hot", qos: .userInteractive)
let slowWorkerQueue = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.slow", qos: .userInitiated, attributes: .concurrent)
let slowWorkerSemaphore = DispatchSemaphore(value: 2)
let eventSignal = DispatchSemaphore(value: 0)
let slowSignal = DispatchSemaphore(value: 0)
let xpcServerQueue = DispatchQueue(label: "uk.craigbass.clearancekit.xpc-server", qos: .userInitiated)

let processTree = ProcessTree(evictionQueue: evictionQueue)
processTree.buildInitialTree()

let interactor = FilterInteractor(
    initialRules: faaPolicy,
    processTree: processTree,
    hotPathQueue: hotPathQueue,
    slowWorkerQueue: slowWorkerQueue,
    slowWorkerSemaphore: slowWorkerSemaphore,
    eventSignal: eventSignal,
    slowSignal: slowSignal
)
let adapter = ESInboundAdapter(interactor: interactor)
let jailAdapter = ESJailAdapter(interactor: interactor)
let server = XPCServer(interactor: interactor, adapter: adapter, jailAdapter: jailAdapter, serverQueue: xpcServerQueue)

interactor.onEvent = { event in
    server.handleEvent(event)
}

server.start()

let initialRules = server.mergedRules()
server.startJailAdapterIfEnabled()
adapter.start(initialRules: initialRules, onXProtectChanged: { server.handleXProtectChange() })

dispatchMain()
