//
//  JailFilterInteractor.swift
//  opfilter
//

import Foundation
import os

// MARK: - JailFilterInteractor

// Called synchronously from the ESJailAdapter ES callback queue.
// Jail policy is pure synchronous logic; responding inline avoids cooperative
// thread saturation and deadline misses when the jail client receives the high
// volume of events its inverted process muting generates. Post-respond work is
// handed off to postRespondHandler immediately after respond() returns.
//
// jailRuleID is resolved by ESJailAdapter from its tracked muted-PID map,
// covering both direct matches (signing ID matches rule) and inherited jails
// (child of a jailed process). Providing the rule ID explicitly means this
// path never needs to match by signing ID.
final class JailFilterInteractor: @unchecked Sendable {
    private let jailRulesStorage: OSAllocatedUnfairLock<[JailRule]>
    private let jailMetricsStorage: OSAllocatedUnfairLock<JailMetrics>
    private let allowlistState: AllowlistState
    private let processTree: ProcessTreeProtocol
    private let postRespondHandler: PostRespondHandler

    init(
        initialJailRules: [JailRule] = [],
        allowlistState: AllowlistState,
        processTree: ProcessTreeProtocol,
        postRespondHandler: PostRespondHandler
    ) {
        self.jailRulesStorage = OSAllocatedUnfairLock(initialState: initialJailRules)
        self.jailMetricsStorage = OSAllocatedUnfairLock(initialState: JailMetrics())
        self.allowlistState = allowlistState
        self.processTree = processTree
        self.postRespondHandler = postRespondHandler
    }

    func handleJailEventSync(_ fileEvent: FileAuthEvent, jailRuleID: UUID) {
        let allowlist = allowlistState.currentAllowlist()

        if isGloballyAllowed(allowlist: allowlist, processPath: fileEvent.processPath, signingID: fileEvent.signingID, teamID: fileEvent.teamID) {
            fileEvent.respond(true, true)
            return
        }

        let jailRules = jailRulesStorage.withLock { $0 }
        guard let rule = jailRules.first(where: { $0.id == jailRuleID }) else {
            fileEvent.respond(true, false)
            return
        }

        let decision = checkJailPaths(rule: rule, path: fileEvent.path, secondaryPath: fileEvent.secondaryPath)
        fileEvent.respond(decision.isAllowed, false)
        jailMetricsStorage.withLock {
            $0.jailEvaluatedCount += 1
            if !decision.isAllowed { $0.jailDenyCount += 1 }
        }

        let ancestors = processTree.ancestors(of: fileEvent.processIdentity)
        postRespondHandler.postRespond(fileEvent: fileEvent, decision: decision, ancestors: ancestors, dwellNanoseconds: 0)
    }

    func jailMetrics() -> JailMetrics {
        jailMetricsStorage.withLock { $0 }
    }

    func updateJailRules(_ rules: [JailRule]) {
        jailRulesStorage.withLock { $0 = rules }
    }
}
