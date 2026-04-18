//
//  BundleUpdaterSignature.swift
//  clearancekit
//

import Foundation

public struct BundleUpdaterSignature: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public let teamID: String
    public let signingID: String

    public init(id: UUID = UUID(), teamID: String, signingID: String) {
        self.id = id
        self.teamID = teamID
        self.signingID = signingID
    }
}
