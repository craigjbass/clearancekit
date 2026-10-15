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

struct WildcardResponsibleProcessCheckError: LocalizedError {
    let entry: ProcessSignature

    var errorDescription: String? {
        "The rule was not saved. The responsible_process_checks entry \"\(entry.description)\" contains a wildcard. List each process by team ID and signing ID."
    }
}

func requireNoWildcardResponsibleProcessChecks(_ checks: [ProcessSignature]?) throws {
    guard let wildcardEntry = checks?.first(where: \.containsWildcard) else { return }
    throw WildcardResponsibleProcessCheckError(entry: wildcardEntry)
}
