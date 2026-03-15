//
//  AppProtection.swift
//  clearancekit
//

import AppKit
import Foundation
import Security

// MARK: - AppProtection

struct AppProtection: Identifiable, Codable {
    let id: UUID
    let appName: String
    let appBundlePath: String
    let bundleID: String
    var ruleIDs: [UUID]
    var isEnabled: Bool
    var snapshotRules: [FAARule]?

    var icon: NSImage {
        let img = NSWorkspace.shared.icon(forFile: appBundlePath)
        img.size = NSSize(width: 32, height: 32)
        return img
    }
}

enum AppProtectionError: LocalizedError {
    case inspectionFailed
    case noProtectablePaths
    case alreadyExists

    var errorDescription: String? {
        switch self {
        case .inspectionFailed:
            return "Could not read code signing information from this application."
        case .noProtectablePaths:
            return "This application has no sandbox or group containers to protect."
        case .alreadyExists:
            return "A protection for this application already exists."
        }
    }
}

// MARK: - App bundle introspection

struct AppBundleInfo {
    let appName: String
    let bundleID: String
    let appPath: String
    let teamID: String
    let signingID: String
    let appGroups: [String]
    let isSandboxed: Bool
}

enum AppBundleIntrospector {
    static func inspect(appURL: URL) -> AppBundleInfo? {
        guard let bundle = Bundle(url: appURL) else { return nil }

        let appName = bundle.infoDictionary?["CFBundleDisplayName"] as? String
            ?? bundle.infoDictionary?[kCFBundleNameKey as String] as? String
            ?? appURL.deletingPathExtension().lastPathComponent

        guard let bundleID = bundle.bundleIdentifier else { return nil }

        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(appURL as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return nil }

        var cfInfo: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &cfInfo) == errSecSuccess,
              let info = cfInfo as? [String: Any] else { return nil }

        let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String ?? ""
        let signingID = info[kSecCodeInfoIdentifier as String] as? String ?? bundleID

        var appGroups: [String] = []
        var isSandboxed = false
        if let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] {
            if let groups = entitlements["com.apple.security.application-groups"] as? [String] {
                appGroups = groups
            }
            isSandboxed = entitlements["com.apple.security.app-sandbox"] as? Bool ?? false
        }

        return AppBundleInfo(
            appName: appName,
            bundleID: bundleID,
            appPath: appURL.path,
            teamID: teamID,
            signingID: signingID,
            appGroups: appGroups,
            isSandboxed: isSandboxed
        )
    }

    static func generateRules(from info: AppBundleInfo) -> [FAARule] {
        let effectiveTeamID = info.teamID.isEmpty ? appleTeamID : info.teamID
        let signature = ProcessSignature(teamID: effectiveTeamID, signingID: info.signingID)
        var rules: [FAARule] = []

        if info.isSandboxed {
            rules.append(FAARule(
                protectedPathPrefix: "/Users/*/Library/Containers/\(info.bundleID)",
                allowedSignatures: [signature]
            ))
        }

        for group in info.appGroups {
            rules.append(FAARule(
                protectedPathPrefix: "/Users/*/Library/Group Containers/\(group)",
                allowedSignatures: [signature]
            ))
        }

        return rules
    }
}
