//
//  SSHKeys.swift
//  clearancekit
//

import Foundation

let sshKeysPreset = AppPreset(
    id: "ssh-keys-protection",
    appName: "SSH Keys",
    description: "Prevents other processes from writing to your SSH key directory. Protects private keys from being replaced or injected by malicious software. Read protection for private keys is not included — the list of legitimate readers (git clients, terminal apps, deployment tools) is too environment-specific for a built-in preset.",
    rules: [
        FAARule(
            id: UUID(uuidString: "D94B5E1E-C467-4AC9-9EB7-9AEFB7020749")!,
            protectedPathPrefix: "/Users/*/.ssh",
            allowedProcessPaths: ["/bin/zsh", "/bin/bash", "/bin/sh", "/bin/dash"],
            allowedSignatures: [
                apple("com.apple.ssh-agent"),
                apple("com.apple.openssh"),
                apple("com.apple.installer"),
                apple("com.apple.SoftwareUpdateAgent"),
                apple("com.apple.mdmclient"),
            ],
            enforceOnWriteOnly: true
        ),
    ],
    symbolName: "key.fill",
    isExperimental: true
)
