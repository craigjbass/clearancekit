//
//  SpotlightRiskGateTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@MainActor
private final class ApplyCounter {
    private(set) var count = 0
    func apply() { count += 1 }
}

@Suite("SpotlightRiskGate")
@MainActor
struct SpotlightRiskGateTests {
    @Test("change without risk applies at once")
    func changeWithoutRiskAppliesAtOnce() {
        let gate = SpotlightRiskGate()
        let counter = ApplyCounter()

        gate.submit([RiskReviewItem(label: "com.apple.finder", risk: .noKnownRisk)], apply: counter.apply)

        #expect(counter.count == 1)
        #expect(gate.pendingChange == nil)
    }

    @Test("risky change waits for confirmation and lists only risky items")
    func riskyChangeWaits() {
        let gate = SpotlightRiskGate()
        let counter = ApplyCounter()

        gate.submit([
            RiskReviewItem(label: "/Users/*/Safe", risk: .noKnownRisk),
            RiskReviewItem(label: "/Users/*/Secrets", risk: .spotlightIndexer),
        ], apply: counter.apply)

        #expect(counter.count == 0)
        #expect(gate.pendingChange?.riskyLabels == ["/Users/*/Secrets"])
    }

    @Test("allow anyway applies the pending change once and clears it")
    func allowAnywayAppliesOnce() {
        let gate = SpotlightRiskGate()
        let counter = ApplyCounter()
        gate.submit([RiskReviewItem(label: "com.apple.mds", risk: .spotlightIndexer)], apply: counter.apply)

        gate.allowAnyway()
        gate.allowAnyway()

        #expect(counter.count == 1)
        #expect(gate.pendingChange == nil)
    }

    @Test("cancel clears the pending change without applying it")
    func cancelClearsWithoutApplying() {
        let gate = SpotlightRiskGate()
        let counter = ApplyCounter()
        gate.submit([RiskReviewItem(label: "com.apple.mds", risk: .spotlightIndexer)], apply: counter.apply)

        gate.cancel()

        #expect(counter.count == 0)
        #expect(gate.pendingChange == nil)
    }
}
