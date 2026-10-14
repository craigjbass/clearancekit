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
    let allowsIndexerSignature = signatures.contains { allowRisk(for: $0) == .spotlightIndexer }
    let allowsIndexerPath = (rule.allowedProcessPaths + rule.allowedAncestorProcessPaths).contains(where: isSpotlightIndexerPath)
    return allowsIndexerSignature || allowsIndexerPath ? .spotlightIndexer : .noKnownRisk
}

private func isSpotlightIndexerPath(_ processPath: String) -> Bool {
    guard !processPath.isEmpty else { return false }
    return spotlightIndexerBinaryNames.contains(URL(fileURLWithPath: processPath).lastPathComponent)
}

private func riskOfMatchCriteria(_ criteria: ProcessMatchCriteria) -> AllowRisk {
    if isSpotlightIndexerPath(criteria.processPath) { return .spotlightIndexer }
    return riskWhenAnyIndexerMatches { criteria.matches(processPath: "", signingID: $0, teamID: appleTeamID) }
}

private func riskWhenAnyIndexerMatches(_ matchesIndexer: (String) -> Bool) -> AllowRisk {
    spotlightIndexerSigningIDs.contains(where: matchesIndexer) ? .spotlightIndexer : .noKnownRisk
}
