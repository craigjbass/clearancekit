//
//  Messages.swift
//  clearancekit
//

import Foundation

private let messagesCoreSignatures: [ProcessSignature] = [
    apple("com.apple.MobileSMS"),
    apple("com.apple.imagent"),
    apple("com.apple.imdpersistence.IMDPersistenceAgent"),
    apple("com.apple.imtransferservices.IMTransferAgent"),
    apple("com.apple.imtranscoding.IMTranscoderAgent"),
    apple("com.apple.MessagesBlastDoorService"),
    apple("com.apple.AddressBook"),
]

private let messagesSpotlightSignatures: [ProcessSignature] = [
    apple("com.apple.mdwrite"),
]

let messagesPreset = AppPreset(
    id: "messages-data-protection",
    appName: "Messages",
    appBundlePath: "/System/Applications/Messages.app",
    description: "Prevents other processes from reading your Messages database, attachments, and chat history. Only Messages and its sync and transfer agents may open files in the Messages data directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-0007-0001-0001-000000000001")!,
            protectedPathPrefix: "/Users/*/Library/Messages",
            allowedSignatures: messagesCoreSignatures + messagesSpotlightSignatures
        ),
    ]
)
