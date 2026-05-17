//
//  BuiltInBundleAllows.swift
//  opfilter
//

import Foundation

struct BuiltInBundleAllow: Sendable {
    let teamID: String
    let signingID: String
    let requiredUID: uid_t?
    let criterion: String

    func matches(processTeamID: String, processSigningID: String, processUID: uid_t) -> Bool {
        guard teamID == processTeamID, signingID == processSigningID else { return false }
        if let requiredUID, requiredUID != processUID { return false }
        return true
    }
}

let builtInBundleAllows: [BuiltInBundleAllow] = [
    BuiltInBundleAllow(
        teamID: appleTeamID,
        signingID: "com.apple.DesktopServicesHelper",
        requiredUID: 0,
        criterion: "system file helper"
    ),
    BuiltInBundleAllow(
        teamID: appleTeamID,
        signingID: "com.apple.MobileInstallationHelperService",
        requiredUID: nil,
        criterion: "app store installer"
    ),
    BuiltInBundleAllow(
        teamID: appleTeamID,
        signingID: "com.apple.installd",
        requiredUID: 0,
        criterion: "system installer daemon"
    ),
]
