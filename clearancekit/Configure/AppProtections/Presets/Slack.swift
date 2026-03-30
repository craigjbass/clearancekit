//
//  Slack.swift
//  clearancekit
//

import Foundation

private let slackSignatures: [ProcessSignature] = [
    sig("BQR82RBBHL", "com.tinyspeck.slackmacgap"),
    sig("BQR82RBBHL", "com.tinyspeck.slackmacgap.helper"),
    sig("BQR82RBBHL", "chrome_crashpad_handler"),
]

let slackPreset = AppPreset(
    id: "slack-data-protection",
    appName: "Slack",
    appBundlePath: "/Applications/Slack.app",
    description: "Prevents other processes from reading Slack's local data and cache. Only Slack and its helpers may open files in its data directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "AEB805E5-F1F5-4717-B0E5-42FA599FCDB6")!,
            protectedPathPrefix: "/Users/*/Library/Application Support/Slack",
            allowedSignatures: slackSignatures
        ),
        FAARule(
            id: UUID(uuidString: "4B6583B8-A7A0-4C7B-A3F2-7B6AB1D4DD7B")!,
            protectedPathPrefix: "/Users/*/Library/Caches/com.tinyspeck.slackmacgap",
            allowedSignatures: [
                sig("BQR82RBBHL", "com.tinyspeck.slackmacgap"),
            ]
        ),
    ]
)
