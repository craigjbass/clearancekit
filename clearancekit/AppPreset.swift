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

    var icon: NSImage {
        let img = NSWorkspace.shared.icon(forFile: appBundlePath)
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
}

// MARK: - Built-in presets

private func apple(_ signingID: String) -> ProcessSignature {
    ProcessSignature(teamID: appleTeamID, signingID: signingID)
}

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
                allowedSignatures: [
                    apple("com.apple.Safari"),
                    apple("com.apple.cloudd"),
                    apple("com.apple.WebKit.WebContent"),
                    apple("com.apple.Safari.History"),
                    apple("com.apple.Safari.SandboxBroker"),
                    apple("com.apple.SafariBookmarksSyncAgent"),
                    apple("com.apple.AuthenticationServicesCore.AuthenticationServicesAgent"),
                ]
            ),
            FAARule(
                id: UUID(uuidString: "A1B2C3D4-0001-0001-0001-000000000002")!,
                protectedPathPrefix: "/Users/*/Library/Containers/com.apple.Safari",
                allowedSignatures: [
                    apple("com.apple.Safari"),
                    apple("com.apple.cloudd"),
                    apple("com.apple.WebKit.WebContent"),
                    apple("com.apple.Safari.History"),
                    apple("com.apple.Safari.SandboxBroker"),
                    apple("com.apple.SafariBookmarksSyncAgent"),
                    apple("com.apple.AuthenticationServicesCore.AuthenticationServicesAgent"),
                    apple("com.apple.SafariPlatformSupport.Helper"),
                    apple("com.apple.WebKit.GPU")
                ]
            ),
            FAARule(
                id: UUID(uuidString: "A1B2C3D4-0001-0001-0001-000000000003")!,
                protectedPathPrefix: "/Users/*/Library/Group Containers/group.com.apple.safari",
                allowedSignatures: [apple("com.apple.Safari")]
            ),
        ]
    ),
]
