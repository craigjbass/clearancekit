//
//  SpotlightProtection.swift
//  clearancekit
//

import Foundation

let spotlightProtectionPreset = AppPreset(
    id: "spotlight-importer-protection",
    appName: "Spotlight Importer Protection",
    description: "Blocks unauthorised Spotlight importer plugins from being dropped into your user Spotlight directory. Malicious .mdimporter bundles placed here execute code as you during file indexing.",
    rules: [
        FAARule(
            id: UUID(uuidString: "265DAC18-97D3-4637-B669-B767DBEC4FCF")!,
            protectedPathPrefix: "/Users/*/Library/Spotlight",
            allowedSignatures: [
                apple("com.apple.installer"),
                apple("com.apple.SoftwareUpdateAgent"),
                apple("com.apple.mdmclient"),
            ],
            enforceOnWriteOnly: true
        ),
    ],
    symbolName: "magnifyingglass.circle.fill",
    isExperimental: true
)
