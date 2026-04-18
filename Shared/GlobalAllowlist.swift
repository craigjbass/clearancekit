//
//  GlobalAllowlist.swift
//  clearancekit
//
//  Global process allowlist that bypasses all FAA policy rules.
//  Any process matching an entry is allowed to access any FAA-protected path
//  regardless of the active FAA policy.
//
//  Three tiers, evaluated in order (first match wins):
//    1. Baseline — compiled in; covers essential Apple system processes.
//    2. Managed  — delivered via MDM / .mobileconfig (GlobalAllowlist key).
//    3. User     — persisted in signed JSON on disk; editable via the GUI.
//

import Foundation

// MARK: - AllowlistEntry

public struct AllowlistEntry: Identifiable, Codable {
    public let id: UUID
    /// Signing ID to match. Empty if this is a path-based entry.
    public var signingID: String
    /// Process executable path to match. Empty if this is a signing-ID-based entry.
    public var processPath: String
    /// If true, the process must be an Apple platform binary (empty team ID in ES audit token).
    public var platformBinary: Bool
    /// Additional team ID constraint for non-platform-binary entries. Empty = any team.
    public var teamID: String

    public init(
        id: UUID = UUID(),
        signingID: String = "",
        processPath: String = "",
        platformBinary: Bool = false,
        teamID: String = ""
    ) {
        self.id = id
        self.signingID = signingID
        self.processPath = processPath
        self.platformBinary = platformBinary
        self.teamID = teamID
    }

    public func matches(processPath: String, signingID: String, teamID: String) -> Bool {
        if platformBinary {
            guard teamID == "apple" else { return false }
        } else if !self.teamID.isEmpty {
            guard teamID == self.teamID else { return false }
        }
        if !self.signingID.isEmpty { return self.signingID == "*" || signingID == self.signingID }
        if !self.processPath.isEmpty { return processPath == self.processPath }
        return false
    }
}

// MARK: - AncestorAllowlistEntry

/// An entry in the global ancestor allowlist.
///
/// When any ancestor in the calling-process chain matches this entry, access is
/// granted globally — bypassing all FAA policy rules — regardless of the
/// immediate process identity. This mirrors `AllowlistEntry` semantics but
/// applies to the ancestry chain rather than the immediate caller.
public struct AncestorAllowlistEntry: Identifiable, Codable {
    public let id: UUID
    /// Signing ID to match. Empty if this is a path-based entry.
    public var signingID: String
    /// Process executable path to match. Empty if this is a signing-ID-based entry.
    public var processPath: String
    /// If true, the ancestor must be an Apple platform binary (empty team ID).
    public var platformBinary: Bool
    /// Additional team ID constraint for non-platform-binary entries. Empty = any team.
    public var teamID: String

    public init(
        id: UUID = UUID(),
        signingID: String = "",
        processPath: String = "",
        platformBinary: Bool = false,
        teamID: String = ""
    ) {
        self.id = id
        self.signingID = signingID
        self.processPath = processPath
        self.platformBinary = platformBinary
        self.teamID = teamID
    }

    public func matchesAncestor(path: String, signingID: String, teamID: String) -> Bool {
        if platformBinary {
            guard teamID == "apple" else { return false }
        } else if !self.teamID.isEmpty {
            guard teamID == self.teamID else { return false }
        }
        if !self.signingID.isEmpty { return self.signingID == "*" || signingID == self.signingID }
        if !self.processPath.isEmpty { return path == self.processPath }
        return false
    }
}

// MARK: - Evaluation

public func isGloballyAllowed(
    allowlist: [AllowlistEntry],
    processPath: String,
    signingID: String,
    teamID: String
) -> Bool {
    allowlist.contains { $0.matches(processPath: processPath, signingID: signingID, teamID: teamID) }
}

/// Returns true if any ancestor in `ancestors` matches an entry in `ancestorAllowlist`.
public func isGloballyAllowedByAncestry(
    ancestorAllowlist: [AncestorAllowlistEntry],
    ancestors: [AncestorInfo]
) -> Bool {
    ancestors.contains { ancestor in
        ancestorAllowlist.contains { $0.matchesAncestor(path: ancestor.path, signingID: ancestor.signingID, teamID: ancestor.teamID) }
    }
}

// MARK: - Baseline allowlist

private func signingEntry(n: Int, signingID: String) -> AllowlistEntry {
    AllowlistEntry(
        id: UUID(uuidString: String(format: "B0000000-0000-0000-0000-%012X", n))!,
        signingID: signingID,
        platformBinary: true
    )
}

public let baselineAllowlist: [AllowlistEntry] = [
    signingEntry(n: 1,  signingID: "com.apple.mdworker"),
    signingEntry(n: 2,  signingID: "com.apple.mdworker_shared"),
    signingEntry(n: 3,  signingID: "com.apple.mds"),
    signingEntry(n: 4,  signingID: "com.apple.apfsd"),
    signingEntry(n: 5,  signingID: "com.apple.deleted"),
    signingEntry(n: 6,  signingID: "com.apple.mdsync"),
    signingEntry(n: 7,  signingID: "com.apple.containermanagerd"),
    signingEntry(n: 8,  signingID: "com.apple.containermanagerd_system"),
    signingEntry(n: 9,  signingID: "com.apple.secinitd"),
    signingEntry(n: 10, signingID: "com.apple.CrashReporter"),
    signingEntry(n: 11, signingID: "com.apple.filecoordinationd"),
    signingEntry(n: 12, signingID: "com.apple.ANECompilerService"),
    signingEntry(n: 13, signingID: "com.apple.WebKit.Networking"),
    signingEntry(n: 14, signingID: "com.apple.finder"),
    signingEntry(n: 15, signingID: "com.apple.appkit.xpc.openAndSavePanelService"),
    signingEntry(n: 16, signingID: "com.apple.lsd"),
    signingEntry(n: 17, signingID: "com.apple.logd_helper"),
    signingEntry(n: 18, signingID: "com.apple.settings.PrivacySecurity.extension"),
    signingEntry(n: 19, signingID: "com.apple.iconservicesagent"),
    signingEntry(n: 20, signingID: "com.apple.siriknowledged"),
    signingEntry(n: 21, signingID: "com.apple.PerfPowerServices"),
    signingEntry(n: 22, signingID: "com.apple.spotlightknowledged"),
    signingEntry(n: 23, signingID: "com.apple.BiomeAgent"),
    signingEntry(n: 24, signingID: "com.apple.duetexpertd"),
    signingEntry(n: 25, signingID: "com.apple.findmy.findmylocateagent"),
    signingEntry(n: 26, signingID: "com.apple.corespotlightd"),
    signingEntry(n: 27, signingID: "com.apple.xpc.launchd"),
    signingEntry(n: 28, signingID: "com.apple.cloudd"),
    signingEntry(n: 29, signingID: "com.apple.ScopedBookmarkAgent"),
    signingEntry(n: 30, signingID: "com.apple.talagent"),
    signingEntry(n: 31, signingID: "com.apple.intelligenceplatform.IntelligencePlatformComputeService"),
    signingEntry(n: 32, signingID: "com.apple.coreservices.useractivityd"),
    signingEntry(n: 33, signingID: "com.apple.ctcategories.service"),
    signingEntry(n: 34, signingID: "com.apple.XprotectFramework.AnalysisService"),
    signingEntry(n: 35, signingID: "com.apple.localizationswitcherd"),
    signingEntry(n: 36, signingID: "com.apple.intents.intents-helper"),
]

// MARK: - XProtect enumeration

/// Scans the XProtect bundle's MacOS directory at runtime and returns one
/// platform-binary allowlist entry per executable found. Called on opfilter
/// startup (and resync) so newly-shipped XProtect remediators are picked up
/// automatically after an XProtect update, without a clearancekit update.
public func enumerateXProtectEntries() -> [AllowlistEntry] {
    let macosDir = URL(fileURLWithPath: "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS")
    guard let items = try? FileManager.default.contentsOfDirectory(
        at: macosDir,
        includingPropertiesForKeys: [.isRegularFileKey],
        options: .skipsHiddenFiles
    ) else { return [] }
    return items.compactMap { url -> AllowlistEntry? in
        guard (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else { return nil }
        return AllowlistEntry(processPath: url.path, platformBinary: true)
    }.sorted { $0.processPath < $1.processPath }
}
