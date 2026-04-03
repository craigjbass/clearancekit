//
//  Chrome.swift
//  clearancekit
//

import Foundation

let chromePreset = AppPreset(
    id: "chrome-data-protection",
    appName: "Google Chrome",
    appBundlePath: "/Applications/Google Chrome.app",
    description: "Prevents other processes from reading Chrome's cookies, history, and profile data. Only Chrome and its helpers may open files in its data directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "2E8546E3-C08A-4877-986D-3E676A4B96F3")!,
            protectedPathPrefix: "/Users/*/Library/Application Support/Google",
            allowedSignatures: [
                sig("EQHXZ8M8AV", "com.google.Chrome.helper"),
                sig("EQHXZ8M8AV", "com.google.Chrome"),
                sig("EQHXZ8M8AV", "com.google.GoogleUpdater"),
                sig("EQHXZ8M8AV", "chrome_crashpad_handler"),
                apple("com.apple.LoginItems-Settings.extension"),
                apple("com.apple.Safari.BrowserDataImportingService"),
            ],
            allowedAncestorSignatures: [
                sig("EQHXZ8M8AV", "com.google.GoogleUpdater"),
            ]
        ),
        FAARule(
            id: UUID(uuidString: "09627815-1A42-4ABD-968E-F2AE94745282")!,
            protectedPathPrefix: "/Users/*/Library/Caches/Google",
            allowedSignatures: [
                sig("EQHXZ8M8AV", "com.google.Chrome.helper"),
                sig("EQHXZ8M8AV", "com.google.Chrome"),
            ]
        ),
    ]
)
