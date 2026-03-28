//
//  HEY.swift
//  clearancekit
//

import Foundation

let heyPreset = AppPreset(
    id: "hey-data-protection",
    appName: "HEY",
    appBundlePath: "/Applications/HEY.app",
    description: "Prevents other processes from reading HEY's local data. Only HEY itself may open files in its application support directory.",
    rules: [
        FAARule(
            id: UUID(uuidString: "CBAA6EE3-009A-4969-B516-892162682F74")!,
            protectedPathPrefix: "/Users/*/Library/Application Support/HEY",
            allowedSignatures: [
                sig("473F8PJA84", "com.hey.app.desktop"),
                sig("473F8PJA84", "com.hey.app.desktop.helper"),
                sig("473F8PJA84", "chrome_crashpad_handler"),
            ],
            allowedAncestorSignatures: [
                sig("473F8PJA84", "com.hey.app.desktop"),
            ]
        ),
    ]
)
