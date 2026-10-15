//
//  AllowRiskGate.swift
//  clearancekit
//

import Foundation
import Combine

enum AllowRiskCopy {
    static let allowAnyway = "Allow anyway"
    static let cancel = "Cancel"

    static func title(for risk: AllowRisk) -> String {
        switch risk {
        case .noKnownRisk: return ""
        case .spotlightIndexer: return "Allow a Spotlight indexer?"
        case .webKitService: return "Allow a WebKit service?"
        case .responsibleProcessAllow: return "Allow an app and the processes it starts?"
        }
    }

    static func body(for risk: AllowRisk) -> String {
        switch risk {
        case .noKnownRisk: return ""
        case .spotlightIndexer: return "Spotlight indexers read files for any user on this Mac. If you allow an indexer, any account can read protected files with `mdimport` and search their contents with `mdfind`."
        case .webKitService: return "Any app that shows web content can use WebKit services to read files this entry allows."
        case .responsibleProcessAllow: return "A WebKit service opened this file for this app. If you allow this app, the rule also allows web content loaded by any process the app starts."
        }
    }
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
    let risks: [AllowRisk]
    let apply: @MainActor () -> Void
}

@MainActor
final class AllowRiskGate: ObservableObject {
    @Published private(set) var pendingChange: PendingRiskyChange?

    func submit(_ items: [RiskReviewItem], apply: @escaping @MainActor () -> Void) {
        let riskyItems = items.filter { $0.risk != .noKnownRisk }
        guard !riskyItems.isEmpty else {
            apply()
            return
        }
        var risks: [AllowRisk] = []
        for item in riskyItems where !risks.contains(item.risk) { risks.append(item.risk) }
        pendingChange = PendingRiskyChange(riskyLabels: riskyItems.map(\.label), risks: risks, apply: apply)
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
