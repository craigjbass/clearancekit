//
//  SpotlightRiskGate.swift
//  clearancekit
//

import Foundation
import Combine

enum SpotlightIndexerRiskCopy {
    static let title = "Allow a Spotlight indexer?"
    static let body = "Spotlight indexers read files for any user on this Mac. If you allow an indexer, any account can read protected files with `mdimport` and search their contents with `mdfind`."
    static let allowAnyway = "Allow anyway"
    static let cancel = "Cancel"
}

struct RiskReviewItem {
    let label: String
    let risk: AllowRisk
}

extension RiskReviewItem {
    static func items(for rules: [FAARule]) -> [RiskReviewItem] {
        rules.map { RiskReviewItem(label: $0.protectedPathPrefix, risk: allowRisk(for: $0)) }
    }
}

struct PendingRiskyChange: Identifiable {
    let id = UUID()
    let riskyLabels: [String]
    let apply: @MainActor () -> Void
}

@MainActor
final class SpotlightRiskGate: ObservableObject {
    @Published private(set) var pendingChange: PendingRiskyChange?

    func submit(_ items: [RiskReviewItem], apply: @escaping @MainActor () -> Void) {
        let riskyLabels = items.filter { $0.risk == .spotlightIndexer }.map(\.label)
        guard !riskyLabels.isEmpty else {
            apply()
            return
        }
        pendingChange = PendingRiskyChange(riskyLabels: riskyLabels, apply: apply)
    }

    func allowAnyway() {
        guard let change = pendingChange else { return }
        pendingChange = nil
        change.apply()
    }

    func cancel() {
        pendingChange = nil
    }
}
