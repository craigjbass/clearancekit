//
//  MullvadVPN.swift
//  clearancekit
//

import Foundation

let mullvadPreset = AppPreset(
    id: "mullvad-vpn-data-protection",
    appName: "Mullvad VPN",
    appBundlePath: "/Applications/Mullvad VPN.app",
    description: "Prevents other processes from reading Mullvad VPN's local application data. Only Mullvad VPN and its privileged helper may open files in its data directory.",
    rules: [
        FAARule(
            id: UUID(uuidString: "DC713D06-077B-4243-A3C7-B713AD724E47")!,
            protectedPathPrefix: "/Users/*/Library/Application Support/Mullvad VPN",
            allowedSignatures: [
                sig("CKG9MXH72F", "net.mullvad.vpn"),
                sig("CKG9MXH72F", "net.mullvad.vpn.helper"),
            ]
        ),
    ]
)
