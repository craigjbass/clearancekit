//
//  MCPAllowRiskGate.swift
//  clearancekit
//

import Foundation

enum AllowRiskAcknowledgement {
    case acknowledged
    case notAcknowledged
}

struct AllowRiskNotAcknowledgedError: LocalizedError {
    let risk: AllowRisk

    var errorDescription: String? {
        "The rule was not saved. It allows \(risk.subject). \(AllowRiskCopy.body(for: risk)) To save the rule anyway, call the tool again with acknowledge_allow_risk: true."
    }
}

func requireAllowRiskAcknowledgement(for rule: FAARule, acknowledgement: AllowRiskAcknowledgement) throws {
    let risk = allowRisk(for: rule)
    guard risk != .noKnownRisk else { return }
    guard case .notAcknowledged = acknowledgement else { return }
    throw AllowRiskNotAcknowledgedError(risk: risk)
}
