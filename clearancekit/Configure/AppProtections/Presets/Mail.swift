//
//  Mail.swift
//  clearancekit
//

import Foundation

private let mailCoreSignatures: [ProcessSignature] = [
    apple("com.apple.mail"),
    apple("com.apple.email.maild"),
    apple("com.apple.MailServiceAgent"),
    apple("com.apple.MailTrafficAgent"),
    apple("com.apple.mail.XPCHelper"),
    apple("com.apple.exchange.exchangesyncd"),
    apple("com.apple.accountsd"),
    apple("com.apple.cloudd"),
    apple("com.apple.IMCore"),
]

private let mailSpotlightSignatures: [ProcessSignature] = [
    apple("com.apple.mds"),
    apple("com.apple.mds_stores"),
    apple("com.apple.mdworker_shared"),
]

private let mailSandboxSignatures: [ProcessSignature] = [
    apple("com.apple.secinitd"),
    apple("com.apple.containermanagerd"),
    apple("com.apple.syncdefaultsd"),
    apple("com.apple.WebKit.Networking"),
]

let mailPreset = AppPreset(
    id: "mail-data-protection",
    appName: "Mail",
    appBundlePath: "/System/Applications/Mail.app",
    description: "Prevents other processes from reading your Mail store, attachments, and account data. Only Mail and its sync agents may open files in the Mail data directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-0003-0001-0001-000000000001")!,
            protectedPathPrefix: "/Users/*/Library/Mail",
            allowedSignatures: mailCoreSignatures + mailSpotlightSignatures
        ),
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-0003-0001-0001-000000000002")!,
            protectedPathPrefix: "/Users/*/Library/Containers/com.apple.mail",
            allowedSignatures: mailCoreSignatures + mailSandboxSignatures
        ),
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-0003-0001-0001-000000000003")!,
            protectedPathPrefix: "/Users/*/Library/Group Containers/group.com.apple.mail.shared",
            allowedSignatures: mailCoreSignatures
        ),
    ]
)
