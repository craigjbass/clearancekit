//
//  InMemoryCodeProtection.swift
//  clearancekit
//

import Foundation

let inMemoryCodeProtectionPreset = AppPreset(
    id: "in-memory-code-loading-protection",
    appName: "In-Memory Code Loading",
    description: "Blocks creation of temporary files used by the deprecated NSCreateObjectFileImageFromMemory API — a technique used by in-memory code loaders and certain injection tools. No legitimate software should need to create files matching this pattern.",
    rules: [
        FAARule(
            id: UUID(uuidString: "7F541614-31BF-4525-803F-794C578771E5")!,
            protectedPathPrefix: "/private/var/folders/**/NSCreateObjectFileImageFromMemory-*",
            enforceOnWriteOnly: true
        ),
    ],
    symbolName: "memorychip.fill",
    isExperimental: true
)
