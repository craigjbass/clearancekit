//
//  BundleProtectionEvaluator.swift
//  opfilter
//

import Foundation

final class BundleProtectionEvaluator: @unchecked Sendable {
    // Stable sentinel used as ruleID for all bundle-protection decisions.
    // Generated once with `uuidgen` and must never change.
    static let sentinelRuleID = UUID(uuidString: "7358F9B3-7037-4421-90C5-B136AAC9C2E5")!

    private let cache: BundleCodesignCache
    private let updaterSignaturesProvider: @Sendable () -> [BundleUpdaterSignature]

    init(
        cache: BundleCodesignCache,
        updaterSignaturesProvider: @escaping @Sendable () -> [BundleUpdaterSignature]
    ) {
        self.cache = cache
        self.updaterSignaturesProvider = updaterSignaturesProvider
    }

    /// Hot-path gate: returns true when the event should be forced to the slow path.
    func isBundleWrite(path: String, accessKind: AccessKind) -> Bool {
        guard accessKind == .write else { return false }
        guard let bundlePath = BundlePath.extract(from: path) else { return false }
        // Renaming/moving the bundle root itself (e.g. Squirrel swapping the whole .app) is not
        // a tamper event — that operation is governed by FAA policy rules, not bundle protection.
        return path != bundlePath
    }

    /// Slow-path evaluation. Returns nil → not a bundle write or bundle is unsigned → fall through.
    func evaluate(
        accessPath: String,
        processTeamID: String,
        processSigningID: String,
        accessKind: AccessKind
    ) -> PolicyDecision? {
        guard let bundlePath = BundlePath.extract(from: accessPath) else { return nil }
        guard accessKind == .write else { return nil }
        guard accessPath != bundlePath else { return nil }
        guard let bundleSignatures = cache.signatures(forBundlePath: bundlePath) else { return nil }

        let updaters = updaterSignaturesProvider()
        if updaters.contains(where: { $0.teamID == processTeamID && $0.signingID == processSigningID }) {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "external updater"
            )
        }

        if processTeamID == bundleSignatures.teamID {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "bundle self-signer"
            )
        }

        return .denied(
            ruleID: BundleProtectionEvaluator.sentinelRuleID,
            ruleName: bundlePath,
            ruleSource: .builtin,
            allowedCriteria: "bundle signing identity \(bundleSignatures.teamID)"
        )
    }
}
