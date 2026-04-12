//
//  KeychainProtection.swift
//  clearancekit
//

import Foundation

private let keychainDaemonSignatures: [ProcessSignature] = [
    apple("com.apple.secd"),
    apple("com.apple.security"),
    apple("com.apple.keychainsyncingoverictransport"),
    apple("com.apple.securityd"),
    apple("com.apple.installer"),
    apple("com.apple.SoftwareUpdateAgent"),
    apple("com.apple.mdmclient"),
]

let keychainProtectionPreset = AppPreset(
    id: "keychain-write-protection",
    appName: "Keychain Write Protection",
    description: "Prevents unauthorised processes from modifying keychain databases on disk. Only Apple's keychain daemon and security framework may write to these files.",
    rules: [
        FAARule(
            id: UUID(uuidString: "7D2D7879-5F65-4CE1-9556-CDC2EE9DFD43")!,
            protectedPathPrefix: "/Users/*/Library/Keychains",
            allowedSignatures: keychainDaemonSignatures,
            enforceOnWriteOnly: true
        ),
        FAARule(
            id: UUID(uuidString: "C3AF22BA-6377-47B6-AB6E-56C015D821CE")!,
            protectedPathPrefix: "/Library/Keychains",
            allowedSignatures: keychainDaemonSignatures,
            enforceOnWriteOnly: true
        ),
    ],
    symbolName: "lock.fill",
    isExperimental: true
)
