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

// MARK: - Built-in presets

private func apple(_ signingID: String) -> ProcessSignature {
    ProcessSignature(teamID: appleTeamID, signingID: signingID)
}

private func sig(_ teamID: String, _ signingID: String) -> ProcessSignature {
    ProcessSignature(teamID: teamID, signingID: signingID)
}

let safariSignatures: [ProcessSignature] = [
    apple("com.apple.Safari"),
    apple("com.apple.cloudd"),
    apple("com.apple.WebKit.WebContent"),
    apple("com.apple.Safari.History"),
    apple("com.apple.Safari.SandboxBroker"),
    apple("com.apple.SafariBookmarksSyncAgent"),
    apple("com.apple.AuthenticationServicesCore.AuthenticationServicesAgent"),
    apple("com.apple.SafariPlatformSupport.Helper"),
    apple("com.apple.WebKit.GPU"),
    apple("com.apple.localizationswitcherd"),
    apple("com.apple.Safari.PasswordBreachAgent"),
    apple("com.apple.Safari.CacheDeleteExtension"),
    apple("com.apple.AuthenticationServices.Helper"),
]

private let discordSignatures: [ProcessSignature] = [
    sig("53Q6R32WPB", "com.hnc.Discord"),
    sig("53Q6R32WPB", "com.hnc.Discord.helper"),
    sig("53Q6R32WPB", "com.hnc.Discord.helper.Renderer"),
    apple("com.apple.xpc.launchd"),
    sig("53Q6R32WPB", "chrome_crashpad_handler"),
]

let builtInPresets: [AppPreset] = [
    AppPreset(
        id: "notes-data-protection",
        appName: "Notes",
        appBundlePath: "/System/Applications/Notes.app",
        description: "Prevents other processes from reading your Notes database and attachments. Only Notes and its extensions may open files in the Notes group container.",
        rules: [
            FAARule(
                id: UUID(uuidString: "A1B2C3D4-0002-0001-0001-000000000001")!,
                protectedPathPrefix: "/Users/*/Library/Group Containers/group.com.apple.notes",
                allowedSignatures: [
                    apple("com.apple.Notes"),
                    apple("com.apple.Notes.WidgetExtension"),
                    apple("com.apple.Notes.QuickLookExtension"),
                    apple("com.apple.Notes.SharingExtension"),
                    apple("com.apple.Notes.SpotlightIndexExtension"),
                    apple("com.apple.Notes.IntentsExtension"),
                    apple("com.apple.LinkedNotesUIService"),
                ]
            ),
        ]
    ),
    AppPreset(
        id: "safari-data-protection",
        appName: "Safari",
        appBundlePath: "/Applications/Safari.app",
        description: "Prevents other processes from reading Safari's cookies, history, and stored credentials. Only Safari itself may open files in its data directories.",
        rules: [
            FAARule(
                id: UUID(uuidString: "A1B2C3D4-0001-0001-0001-000000000001")!,
                protectedPathPrefix: "/Users/*/Library/Safari",
                allowedSignatures: safariSignatures + [
                    apple("com.apple.UserEventAgent"),
                    apple("com.apple.SafariNotificationAgent"),
                ]
            ),
            FAARule(
                id: UUID(uuidString: "A1B2C3D4-0001-0001-0001-000000000002")!,
                protectedPathPrefix: "/Users/*/Library/Containers/com.apple.Safari",
                allowedSignatures: safariSignatures
            ),
            FAARule(
                id: UUID(uuidString: "A1B2C3D4-0001-0001-0001-000000000003")!,
                protectedPathPrefix: "/Users/*/Library/Group Containers/group.com.apple.safari",
                allowedSignatures: safariSignatures
            ),
        ]
    ),
    AppPreset(
        id: "hey-data-protection",
        appName: "HEY",
        appBundlePath: "/Applications/HEY.app",
        description: "Prevents other processes from reading HEY's local data. Only HEY itself may open files in its application support directory.",
        rules: [
            FAARule(
                id: UUID(uuidString: "CBAA6EE3-009A-4969-B516-892162682F74")!,
                protectedPathPrefix: "/Users/*/Library/Application Support/HEY",
                allowedSignatures: [
                    sig("473F8PJA84", "com.hey.app.desktop"),
                ]
            ),
        ]
    ),
    AppPreset(
        id: "discord-data-protection",
        appName: "Discord",
        appBundlePath: "/Applications/Discord.app",
        description: "Prevents other processes from reading Discord's local data and cache. Only Discord and its helpers may open files in its data directories.",
        rules: [
            FAARule(
                id: UUID(uuidString: "5E43F67E-2DB2-40EF-9AF8-E542193CECFC")!,
                protectedPathPrefix: "/Users/*/Library/Application Support/discord",
                allowedSignatures: discordSignatures
            ),
            FAARule(
                id: UUID(uuidString: "74F63DEF-A0A2-4C4A-AC7B-A5B47ADAA88A")!,
                protectedPathPrefix: "/Users/*/Library/Caches/com.hnc.Discord",
                allowedSignatures: [
                    sig("53Q6R32WPB", "com.hnc.Discord"),
                ]
            ),
            FAARule(
                id: UUID(uuidString: "A181F1A5-B68C-4E0F-827F-61155A15CE98")!,
                protectedPathPrefix: "/Users/*/Library/Caches/com.hnc.Discord.ShipIt",
                allowedSignatures: [
                    sig("53Q6R32WPB", "com.hnc.Discord"),
                ]
            ),
        ]
    ),
    AppPreset(
        id: "signal-data-protection",
        appName: "Signal",
        appBundlePath: "/Applications/Signal.app",
        description: "Prevents other processes from reading Signal's local messages and attachments. Only Signal and its helpers may open files in its application support directory.",
        rules: [
            FAARule(
                id: UUID(uuidString: "D8D8D470-643F-41F3-8BF0-00D390002311")!,
                protectedPathPrefix: "/Users/*/Library/Application Support/Signal",
                allowedSignatures: [
                    sig("U68MSDN6DR", "org.whispersystems.signal-desktop"),
                    sig("U68MSDN6DR", "org.whispersystems.signal-desktop.helper.Renderer"),
                    sig("U68MSDN6DR", "org.whispersystems.signal-desktop.helper"),
                ]
            ),
        ]
    ),
    AppPreset(
        id: "chrome-data-protection",
        appName: "Google Chrome",
        appBundlePath: "/Applications/Google Chrome.app",
        description: "Prevents other processes from reading Chrome's cookies, history, and profile data. Only Chrome and its helpers may open files in its data directories.",
        rules: [
            FAARule(
                id: UUID(uuidString: "30C8C303-0D9D-4158-BB54-ABCB6DF61316")!,
                protectedPathPrefix: "/Users/*/Library/Application Support/CrashReporter",
                allowedSignatures: [
                    sig("EQHXZ8M8AV", "com.google.Chrome"),
                ]
            ),
            FAARule(
                id: UUID(uuidString: "2E8546E3-C08A-4877-986D-3E676A4B96F3")!,
                protectedPathPrefix: "/Users/*/Library/Application Support/Google",
                allowedSignatures: [
                    sig("EQHXZ8M8AV", "com.google.Chrome.helper"),
                    sig("EQHXZ8M8AV", "com.google.Chrome"),
                    sig("EQHXZ8M8AV", "com.google.GoogleUpdater"),
                    sig("EQHXZ8M8AV", "chrome_crashpad_handler"),
                    apple("com.apple.LoginItems-Settings.extension"),
                    apple("com.apple.Safari.BrowserDataImportingService"),
                ]
            ),
            FAARule(
                id: UUID(uuidString: "09627815-1A42-4ABD-968E-F2AE94745282")!,
                protectedPathPrefix: "/Users/*/Library/Caches/Google",
                allowedSignatures: [
                    sig("EQHXZ8M8AV", "com.google.Chrome.helper"),
                    sig("EQHXZ8M8AV", "com.google.Chrome"),
                ]
            ),
        ]
    ),
]
