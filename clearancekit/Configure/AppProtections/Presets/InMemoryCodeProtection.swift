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
        // The rule blocks the creation of NSCreateObjectFileImageFromMemory-*
        // files. A move of a temporary folder creates no such file, so folders
        // below ** do not need this rule's permission to move.
        FAARule(
            id: UUID(uuidString: "7F541614-31BF-4525-803F-794C578771E5")!,
            protectedPathPrefix: "/private/var/folders/**/NSCreateObjectFileImageFromMemory-*",
            enforceOnWriteOnly: true,
            doubleStarParentMatching: .stopAtDoubleStar
        ),
    ],
    symbolName: "memorychip.fill",
    isExperimental: true
)
