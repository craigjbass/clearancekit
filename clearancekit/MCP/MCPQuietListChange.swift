//
//  MCPQuietListChange.swift
//  clearancekit
//

import Foundation

enum MCPQuietListChangeError: LocalizedError, Equatable {
    case noTarget
    case bothTargets
    case wildcardSignature(ProcessSignature)
    case relativeProcessPath(String)
    case alreadyQuieted(QuietListEntry)

    var errorDescription: String? {
        switch self {
        case .noTarget:
            return "The entry was not saved. Pass signature or process_path."
        case .bothTargets:
            return "The entry was not saved. Pass signature or process_path, not both."
        case .wildcardSignature(let signature):
            return "The entry was not saved. The signature \"\(signature.description)\" contains a wildcard. List each process by team ID and signing ID."
        case .relativeProcessPath(let path):
            return "The entry was not saved. process_path \"\(path)\" is not an absolute path."
        case .alreadyQuieted(let entry):
            return "The entry was not saved. The quiet list entry \(entry.id.uuidString) already quiets this process."
        }
    }
}

private enum MCPQuietTarget {
    case signature(ProcessSignature)
    case processPath(String)
}

func quietListEntryForMCPAdd(
    signature: ProcessSignature?,
    processPath: String?,
    existingEntries: [QuietListEntry]
) throws -> QuietListEntry {
    let entry = try quietListEntry(for: quietTarget(signature: signature, processPath: processPath))
    if let existingEntry = existingEntries.first(where: { $0.matchCriteria == entry.matchCriteria }) {
        throw MCPQuietListChangeError.alreadyQuieted(existingEntry)
    }
    return entry
}

private func quietTarget(signature: ProcessSignature?, processPath: String?) throws -> MCPQuietTarget {
    switch (signature, processPath) {
    case (nil, nil):
        throw MCPQuietListChangeError.noTarget
    case (.some, .some):
        throw MCPQuietListChangeError.bothTargets
    case (.some(let signature), nil):
        return .signature(signature)
    case (nil, .some(let processPath)):
        return .processPath(processPath)
    }
}

private func quietListEntry(for target: MCPQuietTarget) throws -> QuietListEntry {
    switch target {
    case .signature(let signature):
        guard !signature.containsWildcard else { throw MCPQuietListChangeError.wildcardSignature(signature) }
        return .quieting(processPath: "", signingID: signature.signingID, teamID: signature.teamID)
    case .processPath(let processPath):
        guard processPath.hasPrefix("/") else { throw MCPQuietListChangeError.relativeProcessPath(processPath) }
        return .quieting(processPath: processPath, signingID: "", teamID: "")
    }
}
