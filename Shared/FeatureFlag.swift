//
//  FeatureFlag.swift
//

import Foundation

struct FeatureFlag: Codable, Equatable {
    let id: UUID
    let name: String
    let enabled: Bool
}

enum FeatureFlagID {
    static let mcpServerEnabled = UUID(uuidString: "F1A90000-0001-0001-0001-000000000001")!
}
