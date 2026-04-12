//
//  AudioPluginProtection.swift
//  clearancekit
//

import Foundation

// NOTE: This preset intentionally has a narrow allowed list. Users with pro audio
// software (Avid, Native Instruments, Ableton, etc.) should disable this preset
// or add their audio installer's team ID as a custom rule in Policy.
let audioPluginProtectionPreset = AppPreset(
    id: "audio-plugin-write-protection",
    appName: "Audio Plugin Protection",
    description: "Prevents new audio plugins from being installed in system Audio Plug-Ins directories without authorisation. Note: pro audio software installers are not included — disable this preset or add a custom rule if you install third-party audio plugins.",
    rules: [
        FAARule(
            id: UUID(uuidString: "B878A528-7415-494C-AA5B-A6553C6ABC56")!,
            protectedPathPrefix: "/Library/Audio/Plug-Ins/Components",
            allowedSignatures: [
                apple("com.apple.installer"),
                apple("com.apple.SoftwareUpdateAgent"),
                apple("com.apple.mdmclient"),
                apple("com.apple.packagekit"),
            ],
            enforceOnWriteOnly: true
        ),
        FAARule(
            id: UUID(uuidString: "2A17D6B5-1820-4FEE-B080-8564D6D85760")!,
            protectedPathPrefix: "/Library/Audio/Plug-Ins/HAL",
            allowedSignatures: [
                apple("com.apple.installer"),
                apple("com.apple.SoftwareUpdateAgent"),
                apple("com.apple.mdmclient"),
                apple("com.apple.packagekit"),
            ],
            enforceOnWriteOnly: true
        ),
    ],
    symbolName: "waveform.slash",
    isExperimental: true
)
