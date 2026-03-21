//
//  AppPreset.swift
//  clearancekit
//

import AppKit
import Foundation

// MARK: - AppPreset

struct AppPreset: Identifiable {
    let id: String
    let appName: String
    let appBundlePath: String
    let description: String
    let rules: [FAARule]

    var resolvedBundlePath: String? {
        if FileManager.default.fileExists(atPath: appBundlePath) { return appBundlePath }
        let appFileName = URL(fileURLWithPath: appBundlePath).lastPathComponent
        let userAppsPath = ("~/Applications/" + appFileName as NSString).expandingTildeInPath
        if FileManager.default.fileExists(atPath: userAppsPath) { return userAppsPath }
        return nil
    }

    var isInstalled: Bool {
        resolvedBundlePath != nil
    }

    var icon: NSImage {
        let img = NSWorkspace.shared.icon(forFile: resolvedBundlePath ?? appBundlePath)
        img.size = NSSize(width: 32, height: 32)
        return img
    }

    enum EnabledState {
        case enabled
        case partiallyEnabled
        case disabled
    }

    func enabledState(in userRules: [FAARule]) -> EnabledState {
        let matchCount = rules.filter { preset in userRules.contains { $0.id == preset.id } }.count
        if matchCount == rules.count { return .enabled }
        if matchCount > 0 { return .partiallyEnabled }
        return .disabled
    }

    func hasDrifted(in userRules: [FAARule]) -> Bool {
        guard enabledState(in: userRules) == .enabled else { return false }
        return rules.contains { presetRule in
            guard let applied = userRules.first(where: { $0.id == presetRule.id }) else { return false }
            return applied != presetRule
        }
    }
}

// MARK: - Built-in preset helpers

func apple(_ signingID: String) -> ProcessSignature {
    ProcessSignature(teamID: appleTeamID, signingID: signingID)
}

func sig(_ teamID: String, _ signingID: String) -> ProcessSignature {
    ProcessSignature(teamID: teamID, signingID: signingID)
}
