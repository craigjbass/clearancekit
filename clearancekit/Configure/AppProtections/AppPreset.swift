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
    let appBundlePath: String?
    let description: String
    let rules: [FAARule]
    let symbolName: String?
    let isExperimental: Bool

    init(id: String, appName: String, appBundlePath: String? = nil, description: String, rules: [FAARule], symbolName: String? = nil, isExperimental: Bool = false) {
        self.id = id
        self.appName = appName
        self.appBundlePath = appBundlePath
        self.description = description
        self.rules = rules
        self.symbolName = symbolName
        self.isExperimental = isExperimental
    }

    var resolvedBundlePath: String? {
        guard let appBundlePath else { return nil }
        if FileManager.default.fileExists(atPath: appBundlePath) { return appBundlePath }
        let appFileName = URL(fileURLWithPath: appBundlePath).lastPathComponent
        let userAppsPath = ("~/Applications/" + appFileName as NSString).expandingTildeInPath
        if FileManager.default.fileExists(atPath: userAppsPath) { return userAppsPath }
        return nil
    }

    var isInstalled: Bool {
        appBundlePath == nil ? true : resolvedBundlePath != nil
    }

    var icon: NSImage {
        if let symbolName {
            let config = NSImage.SymbolConfiguration(pointSize: 20, weight: .medium)
            if let image = NSImage(systemSymbolName: symbolName, accessibilityDescription: appName) {
                return image.withSymbolConfiguration(config) ?? image
            }
        }
        let img = NSWorkspace.shared.icon(forFile: resolvedBundlePath ?? appBundlePath ?? "")
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
