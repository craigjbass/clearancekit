//
//  Firefox.swift
//  clearancekit
//

import Foundation

private let firefoxSignatures: [ProcessSignature] = [
    sig("43AQ936H96", "org.mozilla.firefox"),
    sig("43AQ936H96", "org.mozilla.updater"),
    sig("43AQ936H96", "org.mozilla.crashreporter"),
    sig("43AQ936H96", "org.mozilla.plugincontainer"),
]

let firefoxPreset = AppPreset(
    id: "firefox-data-protection",
    appName: "Firefox",
    appBundlePath: "/Applications/Firefox.app",
    description: "Prevents other processes from reading Firefox's cookies, history, and profile data. Only Firefox and its helpers may open files in its data directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "640EEB1F-E28A-464B-961C-82D21CD9BD22")!,
            protectedPathPrefix: "/Users/*/Library/Application Support/Firefox",
            allowedSignatures: firefoxSignatures
        ),
        FAARule(
            id: UUID(uuidString: "8472F3F9-521D-48F2-9E0F-171B1FD8CF54")!,
            protectedPathPrefix: "/Users/*/Library/Caches/Firefox",
            allowedSignatures: firefoxSignatures
        ),
    ],
    isExperimental: true
)
