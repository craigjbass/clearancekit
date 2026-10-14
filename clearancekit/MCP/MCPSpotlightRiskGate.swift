//
//  MCPSpotlightRiskGate.swift
//  clearancekit
//

import Foundation

enum SpotlightRiskAcknowledgement {
    case acknowledged
    case notAcknowledged
}

struct SpotlightRiskNotAcknowledgedError: LocalizedError {
    var errorDescription: String? {
        "The rule was not saved. It allows a Spotlight indexer (\(spotlightIndexerSigningIDs.joined(separator: ", "))). \(SpotlightIndexerRiskCopy.body) To save the rule anyway, call the tool again with acknowledge_spotlight_risk: true."
    }
}

func requireSpotlightRiskAcknowledgement(for rule: FAARule, acknowledgement: SpotlightRiskAcknowledgement) throws {
    guard case .spotlightIndexer = allowRisk(for: rule) else { return }
    guard case .notAcknowledged = acknowledgement else { return }
    throw SpotlightRiskNotAcknowledgedError()
}
