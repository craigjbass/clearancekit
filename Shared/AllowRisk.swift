//
//  AllowRisk.swift
//  clearancekit
//

import Foundation

public enum AllowRisk: Hashable {
    case noKnownRisk
    case spotlightIndexer
    case webKitService
    case responsibleProcessAllow
    case broadResponsibleProcessCheck
}

public extension AllowRisk {
    var subject: String {
        switch self {
        case .noKnownRisk: return "no known risk"
        case .spotlightIndexer: return "a Spotlight indexer"
        case .webKitService: return "a WebKit service"
        case .responsibleProcessAllow: return "an app that is the responsible process for WebKit services"
        case .broadResponsibleProcessCheck: return "the processes that an app starts, through a responsible process check outside Apple's WebKit services"
        }
    }
}

public func allowRisk(for signature: ProcessSignature) -> AllowRisk {
    let indexerRisk = riskWhenAnyIndexerMatches { signature.matches(resolvedTeamID: appleTeamID, signingID: $0) }
    guard indexerRisk == .noKnownRisk else { return indexerRisk }
    return signatureMatchesWebKitService(signature) ? .webKitService : .noKnownRisk
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
    if allowsIndexerSignature || allowsIndexerPath { return .spotlightIndexer }
    let allowsUncheckedWebKitService = defaultResponsibleProcessChecks.contains { webKitService in
        guard !rule.responsibleProcessChecks.contains(where: { $0.matches(resolvedTeamID: webKitService.teamID, signingID: webKitService.signingID) }) else { return false }
        let allowedBySignature = signatures.contains { $0.matches(resolvedTeamID: webKitService.teamID, signingID: webKitService.signingID) }
        let allowedByPath = (rule.allowedProcessPaths + rule.allowedAncestorProcessPaths).contains { isWebKitServicePath($0, of: webKitService) }
        return allowedBySignature || allowedByPath
    }
    if allowsUncheckedWebKitService { return .webKitService }
    return rule.responsibleProcessChecks.contains(where: isBroadResponsibleProcessCheck) ? .broadResponsibleProcessCheck : .noKnownRisk
}

private func isBroadResponsibleProcessCheck(_ check: ProcessSignature) -> Bool {
    check.containsWildcard || !defaultResponsibleProcessChecks.contains(check)
}

private func signatureMatchesWebKitService(_ signature: ProcessSignature) -> Bool {
    defaultResponsibleProcessChecks.contains { signature.matches(resolvedTeamID: $0.teamID, signingID: $0.signingID) }
}

private func isWebKitServicePath(_ processPath: String, of webKitService: ProcessSignature) -> Bool {
    guard !processPath.isEmpty else { return false }
    return URL(fileURLWithPath: processPath).lastPathComponent == webKitService.signingID
}

private func isSpotlightIndexerPath(_ processPath: String) -> Bool {
    guard !processPath.isEmpty else { return false }
    return spotlightIndexerBinaryNames.contains(URL(fileURLWithPath: processPath).lastPathComponent)
}

private func riskOfMatchCriteria(_ criteria: ProcessMatchCriteria) -> AllowRisk {
    if isSpotlightIndexerPath(criteria.processPath) { return .spotlightIndexer }
    let indexerRisk = riskWhenAnyIndexerMatches { criteria.matches(processPath: "", signingID: $0, teamID: appleTeamID) }
    guard indexerRisk == .noKnownRisk else { return indexerRisk }
    let allowsWebKitService = defaultResponsibleProcessChecks.contains {
        isWebKitServicePath(criteria.processPath, of: $0)
            || criteria.matches(processPath: "", signingID: $0.signingID, teamID: $0.teamID)
    }
    return allowsWebKitService ? .webKitService : .noKnownRisk
}

private func riskWhenAnyIndexerMatches(_ matchesIndexer: (String) -> Bool) -> AllowRisk {
    spotlightIndexerSigningIDs.contains(where: matchesIndexer) ? .spotlightIndexer : .noKnownRisk
}
