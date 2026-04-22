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
        accessKind == .write && BundlePath.extract(from: path) != nil
    }

    /// Slow-path evaluation. Returns nil → not a bundle write or bundle is unsigned → fall through.
    func evaluate(
        accessPath: String,
        processTeamID: String,
        processSigningID: String,
        processUID: uid_t,
        accessKind: AccessKind,
        ancestors: [AncestorInfo]
    ) -> PolicyDecision? {
        guard let bundlePath = BundlePath.extract(from: accessPath) else { return nil }
        guard accessKind == .write else { return nil }
        guard let bundleSignatures = cache.signatures(forBundlePath: bundlePath) else { return nil }

        let updaters = updaterSignaturesProvider()

        if updaters.contains(where: { $0.matches(teamID: processTeamID, signingID: processSigningID) }) {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "external updater"
            )
        }

        let trustedByAncestorUpdater = ancestors.contains { ancestor in
            updaters.contains { $0.matches(teamID: ancestor.teamID, signingID: ancestor.signingID) }
        }
        if trustedByAncestorUpdater {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "ancestor updater"
            )
        }

        if processTeamID == appleTeamID && processSigningID == "com.apple.DesktopServicesHelper" && processUID == 0 {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "system file helper"
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

        if ancestors.contains(where: { $0.teamID == bundleSignatures.teamID }) {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "ancestor self-signer"
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
