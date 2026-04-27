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
    apple("com.apple.messages.AssistantExtension"),
    apple("com.apple.IMAutomaticHistoryDeletionAgent"),
]

private let messagesSpotlightSignatures: [ProcessSignature] = [
    apple("com.apple.mdwrite"),
]

private let messagesQuickLookSignatures: [ProcessSignature] = [
    apple("com.apple.quicklook.ThumbnailsAgent"),
    apple("com.apple.quicklook.thumbnail.ImageExtension"),
    apple("com.apple.quicklook.QuickLookUIService"),
]

private let messagesMediaSignatures: [ProcessSignature] = [
    apple("com.apple.mediaanalysisd"),
    apple("com.apple.photolibraryd"),
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
            allowedSignatures: messagesCoreSignatures + messagesSpotlightSignatures + messagesQuickLookSignatures + messagesMediaSignatures
        ),
    ]
)
