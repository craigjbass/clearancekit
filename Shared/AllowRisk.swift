//
//  AllowRisk.swift
//  clearancekit
//

import Foundation

public enum AllowRisk: Equatable {
    case noKnownRisk
    case spotlightIndexer
}

public func allowRisk(for signature: ProcessSignature) -> AllowRisk {
    riskWhenAnyIndexerMatches { signature.matches(resolvedTeamID: appleTeamID, signingID: $0) }
}

public func allowRisk(for entry: AllowlistEntry) -> AllowRisk {
    riskOfMatchCriteria(entry.matchCriteria)
}

public func allowRisk(for entry: AncestorAllowlistEntry) -> AllowRisk {
    riskOfMatchCriteria(entry.matchCriteria)
}

public func allowRisk(for rule: FAARule) -> AllowRisk {
    let signatures = rule.allowedSignatures + rule.allowedAncestorSignatures + rule.authorizedSignatures
    let allowsIndexer = signatures.contains { allowRisk(for: $0) == .spotlightIndexer }
    return allowsIndexer ? .spotlightIndexer : .noKnownRisk
}

private func riskOfMatchCriteria(_ criteria: ProcessMatchCriteria) -> AllowRisk {
    riskWhenAnyIndexerMatches { criteria.matches(processPath: "", signingID: $0, teamID: appleTeamID) }
}

private func riskWhenAnyIndexerMatches(_ matchesIndexer: (String) -> Bool) -> AllowRisk {
    spotlightIndexerSigningIDs.contains(where: matchesIndexer) ? .spotlightIndexer : .noKnownRisk
}
