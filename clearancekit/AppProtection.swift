//
//  AppProtection.swift
//  clearancekit
//

import AppKit
import Combine
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
    case alreadyExists

    var errorDescription: String? {
        switch self {
        case .inspectionFailed:
            return "Could not read code signing information from this application."
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

// MARK: - DiscoverySession

@MainActor
final class DiscoverySession: ObservableObject {
    let appInfo: AppBundleInfo

    private static let sessionDuration: TimeInterval = 60

    @Published private(set) var timeRemaining: TimeInterval = sessionDuration
    @Published private(set) var capturedPaths: [String] = []
    @Published private(set) var isComplete = false

    private var timer: Timer?
    private var cancellable: AnyCancellable?
    private var seenPaths: Set<String> = []
    private var previousEventCount = 0

    init(appInfo: AppBundleInfo) {
        self.appInfo = appInfo
        subscribe()
        startTimer()
        XPCClient.shared.beginDiscovery()
    }

    func complete() {
        timer?.invalidate()
        timer = nil
        cancellable = nil
        isComplete = true
        XPCClient.shared.endDiscovery()
    }

    func buildRules() -> [FAARule] {
        let effectiveTeamID = appInfo.teamID.isEmpty ? appleTeamID : appInfo.teamID
        let signature = ProcessSignature(teamID: effectiveTeamID, signingID: appInfo.signingID)
        return capturedPaths.map { FAARule(protectedPathPrefix: $0, allowedSignatures: [signature]) }
    }

    private func subscribe() {
        cancellable = XPCClient.shared.$events
            .receive(on: RunLoop.main)
            .sink { [weak self] events in self?.ingest(events) }
    }

    private func ingest(_ events: [FolderOpenEvent]) {
        let newCount = events.count
        guard newCount > previousEventCount else {
            previousEventCount = newCount
            return
        }
        let newEvents = events.prefix(newCount - previousEventCount)
        previousEventCount = newCount

        for event in newEvents where matchesApp(event) {
            let dir = normalizedParentDirectory(of: event.path)
            guard isInterestingPath(dir), isSpecificEnough(dir) else { continue }
            seenPaths.insert(dir)
        }
        capturedPaths = deduplicatedPaths()
    }

    private func matchesApp(_ event: FolderOpenEvent) -> Bool {
        if !appInfo.signingID.isEmpty && event.signingID == appInfo.signingID { return true }
        return event.processPath.hasPrefix(appInfo.appPath)
    }

    private func normalizedParentDirectory(of path: String) -> String {
        var components = (path as NSString).deletingLastPathComponent
            .components(separatedBy: "/")
        guard components.count >= 4,
              components[1] == "Users",
              !components[2].isEmpty,
              components[2] != "*" else {
            return (path as NSString).deletingLastPathComponent
        }
        components[2] = "*"
        return components.joined(separator: "/")
    }

    private func isInterestingPath(_ path: String) -> Bool {
        let boringPrefixes = [
            "/private/var/folders/", "/System/", "/usr/", "/bin/",
            "/sbin/", "/var/", "/tmp/", "/Library/Caches/", "/Applications/"
        ]
        guard !boringPrefixes.contains(where: { path.hasPrefix($0) }) else { return false }
        return path.contains("/Users/") || path.contains("/Library/")
    }

    // Shared system directories that are meaningless to protect on a per-app basis.
    // Protecting e.g. /Users/*/Library/Preferences would block every app that reads prefs.
    private static let sharedLibraryDirs: [String] = [
        "/Users/*/Library/Preferences",
        "/Users/*/Library/Logs",
        "/Users/*/Library/Cookies",
        "/Users/*/Library/HTTPStorages",
        "/Users/*/Library/WebKit",
        "/Users/*/Library/Saved Application State",
        "/Users/*/Library/Application Scripts",
        "/Users/*/Library/Recent Servers",
    ]

    private func isSpecificEnough(_ path: String) -> Bool {
        // Reject any path that is, or falls under, a known shared directory.
        for shared in Self.sharedLibraryDirs {
            if path == shared || path.hasPrefix(shared + "/") { return false }
        }
        // Require at least /Users/*/<top-level>/<category>/<app-specific>.
        // This rejects /Users/*/Library and /Users/*/Library/Application Support
        // while accepting /Users/*/Library/Application Support/Signal.
        let components = path.components(separatedBy: "/").filter { !$0.isEmpty }
        return components.count >= 5
    }

    private func deduplicatedPaths() -> [String] {
        let sorted = seenPaths.sorted()
        return sorted.filter { path in
            !sorted.contains { other in other != path && path.hasPrefix(other + "/") }
        }
    }

    private func startTimer() {
        timeRemaining = Self.sessionDuration
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.tick() }
        }
    }

    private func tick() {
        guard !isComplete else { return }
        timeRemaining -= 1
        if timeRemaining <= 0 { complete() }
    }
}
