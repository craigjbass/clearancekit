//
//  SSHConfigProtection.swift
//  clearancekit
//

import Foundation

let sshConfigProtectionPreset = AppPreset(
    id: "ssh-config-write-protection",
    appName: "SSH Config Protection",
    description: "Prevents unauthorised processes from modifying SSH server and client configuration. Only Apple system software and MDM clients may write to /etc/ssh/.",
    rules: [
        FAARule(
            id: UUID(uuidString: "A8B38897-26F0-40CB-901C-F7EF765213C8")!,
            protectedPathPrefix: "/etc/ssh/",
            allowedSignatures: [
                apple("com.apple.installer"),
                apple("com.apple.SoftwareUpdateAgent"),
                apple("com.apple.mdmclient"),
            ],
            enforceOnWriteOnly: true
        ),
    ],
    symbolName: "lock.shield",
    isExperimental: true
)
