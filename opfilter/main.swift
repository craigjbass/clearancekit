//
//  main.swift
//  opfilter
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation

private let monitoredPath = "/opt/clearancekit"

XPCClient.shared.start()
ProcessTree.shared.buildInitialTree()

let interactor = FilterInteractor()
let adapter = ESInboundAdapter(interactor: interactor, monitoredPath: monitoredPath)
adapter.start()

dispatchMain()
