//
//  Safari.swift
//  clearancekit
//

import Foundation

private let safariSignatures: [ProcessSignature] = [
    apple("com.apple.Safari"),
    apple("com.apple.WebKit.WebContent"),
    apple("com.apple.Safari.History"),
    apple("com.apple.Safari.SandboxBroker"),
    apple("com.apple.SafariBookmarksSyncAgent"),
    apple("com.apple.AuthenticationServicesCore.AuthenticationServicesAgent"),
    apple("com.apple.SafariPlatformSupport.Helper"),
    apple("com.apple.WebKit.GPU"),
    apple("com.apple.Safari.PasswordBreachAgent"),
    apple("com.apple.Safari.CacheDeleteExtension"),
    apple("com.apple.AuthenticationServices.Helper"),
]

let safariPreset = AppPreset(
    id: "safari-data-protection",
    appName: "Safari",
    appBundlePath: "/Applications/Safari.app",
    description: "Prevents other processes from reading Safari's cookies, history, and stored credentials. Only Safari itself may open files in its data directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-0001-0001-0001-000000000001")!,
            protectedPathPrefix: "/Users/*/Library/Safari",
            allowedSignatures: safariSignatures + [
                apple("com.apple.UserEventAgent"),
                apple("com.apple.SafariNotificationAgent"),
                apple("com.apple.Passwords"),
                apple("com.apple.Safari.SafariWidgetExtension"),
            ]
        ),
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-0001-0001-0001-000000000002")!,
            protectedPathPrefix: "/Users/*/Library/Containers/com.apple.Safari",
            allowedSignatures: safariSignatures + [
                apple("com.apple.Passwords"),
                apple("com.apple.quicklook.ThumbnailsAgent"),
                apple("com.apple.quicklook.thumbnail.TextExtension"),
            ]
        ),
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-0001-0001-0001-000000000003")!,
            protectedPathPrefix: "/Users/*/Library/Group Containers/group.com.apple.safari",
            allowedSignatures: safariSignatures
        ),
    ]
)
