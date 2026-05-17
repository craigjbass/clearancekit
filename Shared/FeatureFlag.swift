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
    static let bundleProtectionEnabled = UUID(uuidString: "F7E505BC-C1F8-480E-8679-B5E4B6EA52B4")!
}
