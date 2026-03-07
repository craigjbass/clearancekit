//
//  main.swift
//  opfilter
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation

XPCClient.shared.start()
ProcessTree.shared.buildInitialTree()

let interactor = FilterInteractor(initialRules: faaPolicy)
let adapter = ESInboundAdapter(interactor: interactor)
adapter.start(initialRules: faaPolicy)

XPCClient.shared.onPolicyUpdate = { rules in
    adapter.updatePolicy(rules)
}

dispatchMain()
