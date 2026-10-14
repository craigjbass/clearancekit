//
//  QuietList.swift
//  clearancekit
//

import Foundation

// MARK: - QuietListEntry

public struct QuietListEntry: Identifiable, Codable, Equatable {
    public let id: UUID
    public let signingID: String
    public let processPath: String
    public let platformBinary: Bool
    public let teamID: String

    public init(id: UUID, signingID: String, processPath: String, platformBinary: Bool, teamID: String) {
        self.id = id
        self.signingID = signingID
        self.processPath = processPath
        self.platformBinary = platformBinary
        self.teamID = teamID
    }

    public var matchCriteria: ProcessMatchCriteria {
        ProcessMatchCriteria(signingID: signingID, processPath: processPath, platformBinary: platformBinary, teamID: teamID)
    }

    // An ad-hoc signing ID is chosen by whoever signs the binary, so a process
    // without a team is quieted by its path instead.
    public static func quieting(processPath: String, signingID: String, teamID: String) -> QuietListEntry {
        if teamID.isEmpty || signingID.isEmpty {
            return QuietListEntry(id: UUID(), signingID: "", processPath: processPath, platformBinary: false, teamID: "")
        }
        if teamID == appleTeamID {
            return QuietListEntry(id: UUID(), signingID: signingID, processPath: "", platformBinary: true, teamID: "")
        }
        return QuietListEntry(id: UUID(), signingID: signingID, processPath: "", platformBinary: false, teamID: teamID)
    }
}

// MARK: - NotificationPolicy

public enum NotificationPolicy: Int, Codable {
    case notify = 0
    case quiet = 1
}

public func notificationPolicy(processPath: String, signingID: String, teamID: String, quietList: [QuietListEntry]) -> NotificationPolicy {
    let isQuieted = quietList.contains { $0.matchCriteria.matches(processPath: processPath, signingID: signingID, teamID: teamID) }
    return isQuieted ? .quiet : .notify
}

// MARK: - Spotlight indexers

public let spotlightIndexerSigningIDs = [
    "com.apple.mdworker",
    "com.apple.mdworker_shared",
    "com.apple.mds",
    "com.apple.mdsync",
]

// MARK: - Baseline quiet list

private let baselineQuietListIDPrefix = "D0000000-0000-0000-0000-"
private let baselineQuietListIDSuffixLength = 12

private func baselineQuietListID(position: Int) -> UUID {
    let digits = String(position)
    let padding = String(repeating: "0", count: baselineQuietListIDSuffixLength - digits.count)
    let uuidString = "\(baselineQuietListIDPrefix)\(padding)\(digits)"
    guard let id = UUID(uuidString: uuidString) else {
        preconditionFailure("Invalid baseline quiet list UUID \(uuidString)")
    }
    return id
}

public let baselineQuietList: [QuietListEntry] = spotlightIndexerSigningIDs.enumerated().map { index, signingID in
    QuietListEntry(id: baselineQuietListID(position: index + 1), signingID: signingID, processPath: "", platformBinary: true, teamID: "")
}
