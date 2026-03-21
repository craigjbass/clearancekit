//
//  main.swift
//  opfilter
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation

ProcessTree.shared.buildInitialTree()

let interactor = FilterInteractor(initialRules: faaPolicy)
let adapter = ESInboundAdapter(interactor: interactor)
let jailAdapter = ESJailAdapter(interactor: interactor)
let server = XPCServer(interactor: interactor, adapter: adapter, jailAdapter: jailAdapter)

interactor.onEvent = { event in
    server.handleEvent(event)
}

jailAdapter.start(initialRules: server.mergedJailRules())
adapter.start(initialRules: server.mergedRules(), jailAdapter: jailAdapter, onXProtectChanged: { server.handleXProtectChange() })
server.start()

dispatchMain()
