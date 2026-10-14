//
//  DoubleStarCompatibilityCopy.swift
//  clearancekit
//

import Foundation

enum DoubleStarCompatibilityCopy {
    static let warning = "Directories below `**` can be moved or copied without this rule's permission. Protected files can be moved out of the protected location this way."

    static func bannerTitle(ruleCount: Int) -> String {
        guard ruleCount != 1 else { return "1 rule uses `**` compatibility mode" }
        return "\(ruleCount) rules use `**` compatibility mode"
    }
}
