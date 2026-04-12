//
//  LaunchItemProtection.swift
//  clearancekit
//

import Foundation

private let launchItemInstallerSignatures: [ProcessSignature] = [
    apple("com.apple.installer"),
    apple("com.apple.SoftwareUpdateAgent"),
    apple("com.apple.mdmclient"),
    apple("com.apple.packagekit"),
]

private let launchItemShellPaths = ["/bin/zsh", "/bin/bash", "/bin/sh", "/bin/dash"]

let launchItemProtectionPreset = AppPreset(
    id: "launch-item-write-protection",
    appName: "Launch Item Protection",
    description: "Blocks unauthorised processes from creating or modifying Launch Agents and Daemons — a common malware persistence technique. Legitimate package installers, MDM, and interactive shells are permitted.",
    rules: [
        FAARule(
            id: UUID(uuidString: "B9502AA4-0578-467A-B505-1A972B9749C7")!,
            protectedPathPrefix: "/Users/*/Library/LaunchAgents",
            allowedProcessPaths: launchItemShellPaths,
            allowedSignatures: launchItemInstallerSignatures,
            enforceOnWriteOnly: true
        ),
        FAARule(
            id: UUID(uuidString: "E1FE1B25-EAB5-4C97-8C7F-F9EAC8A59225")!,
            protectedPathPrefix: "/Library/LaunchAgents",
            allowedProcessPaths: launchItemShellPaths,
            allowedSignatures: launchItemInstallerSignatures,
            enforceOnWriteOnly: true
        ),
        FAARule(
            id: UUID(uuidString: "6362F2C6-AEC7-4803-861C-9E6199A45B55")!,
            protectedPathPrefix: "/Library/LaunchDaemons",
            allowedProcessPaths: launchItemShellPaths,
            allowedSignatures: launchItemInstallerSignatures,
            enforceOnWriteOnly: true
        ),
        FAARule(
            id: UUID(uuidString: "8C044D2E-CE3B-473D-9D75-DEE2A6B24B21")!,
            protectedPathPrefix: "/System/Library/LaunchDaemons",
            allowedSignatures: [apple("*")],
            enforceOnWriteOnly: true
        ),
    ],
    symbolName: "arrow.up.circle.fill",
    isExperimental: true
)
