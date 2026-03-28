//
//  Discord.swift
//  clearancekit
//

import Foundation

private let discordSignatures: [ProcessSignature] = [
    sig("53Q6R32WPB", "com.hnc.Discord"),
    sig("53Q6R32WPB", "com.hnc.Discord.helper"),
    sig("53Q6R32WPB", "com.hnc.Discord.helper.Renderer"),
    apple("com.apple.xpc.launchd"),
    sig("53Q6R32WPB", "chrome_crashpad_handler"),
]

let discordPreset = AppPreset(
    id: "discord-data-protection",
    appName: "Discord",
    appBundlePath: "/Applications/Discord.app",
    description: "Prevents other processes from reading Discord's local data and cache. Only Discord and its helpers may open files in its data directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "5E43F67E-2DB2-40EF-9AF8-E542193CECFC")!,
            protectedPathPrefix: "/Users/*/Library/Application Support/discord",
            allowedSignatures: discordSignatures
        ),
        FAARule(
            id: UUID(uuidString: "74F63DEF-A0A2-4C4A-AC7B-A5B47ADAA88A")!,
            protectedPathPrefix: "/Users/*/Library/Caches/com.hnc.Discord",
            allowedSignatures: [
                sig("53Q6R32WPB", "com.hnc.Discord"),
            ]
        ),
        FAARule(
            id: UUID(uuidString: "A181F1A5-B68C-4E0F-827F-61155A15CE98")!,
            protectedPathPrefix: "/Users/*/Library/Caches/com.hnc.Discord.ShipIt",
            allowedSignatures: [
                sig("53Q6R32WPB", "com.hnc.Discord"),
            ]
        ),
    ]
)
