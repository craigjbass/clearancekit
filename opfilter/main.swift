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
let server = XPCServer(interactor: interactor, adapter: adapter)

interactor.onEvent = { event in
    server.handleEvent(event)
}

adapter.start(initialRules: server.mergedRules())
server.start()

dispatchMain()
