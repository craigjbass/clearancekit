//
//  MCPRuleChange.swift
//  clearancekit
//

import Foundation

func ruleForMCPAdd(
    id: UUID,
    protectedPathPrefix: String,
    allowedSignatures: [ProcessSignature],
    enforceOnWriteOnly: Bool,
    doubleStarParentMatching: DoubleStarParentMatching,
    responsibleProcessChecks: [ProcessSignature]?
) -> FAARule {
    FAARule(
        id: id,
        protectedPathPrefix: protectedPathPrefix,
        source: .user,
        allowedSignatures: allowedSignatures,
        enforceOnWriteOnly: enforceOnWriteOnly,
        doubleStarParentMatching: doubleStarParentMatching,
        responsibleProcessChecks: responsibleProcessChecks ?? defaultResponsibleProcessChecks
    )
}

func ruleForMCPUpdate(
    existing: FAARule,
    allowedSignatures: [ProcessSignature],
    enforceOnWriteOnly: Bool,
    doubleStarParentMatching: DoubleStarParentMatching,
    responsibleProcessChecks: [ProcessSignature]?
) -> FAARule {
    FAARule(
        id: existing.id,
        protectedPathPrefix: existing.protectedPathPrefix,
        source: existing.source,
        allowedProcessPaths: existing.allowedProcessPaths,
        allowedSignatures: allowedSignatures,
        allowedAncestorProcessPaths: existing.allowedAncestorProcessPaths,
        allowedAncestorSignatures: existing.allowedAncestorSignatures,
        enforceOnWriteOnly: enforceOnWriteOnly,
        doubleStarParentMatching: doubleStarParentMatching,
        responsibleProcessChecks: responsibleProcessChecks ?? existing.responsibleProcessChecks
    )
}
