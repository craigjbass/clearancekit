//
//  Contacts.swift
//  clearancekit
//

import Foundation

private let contactsCoreSignatures: [ProcessSignature] = [
    apple("com.apple.AddressBook"),
    apple("com.apple.AddressBook.abd"),
    apple("com.apple.contactsd"),
    apple("com.apple.accountsd"),
    apple("com.apple.AddressBookSourceSync"),
    apple("com.apple.ABAssistantService"),
    apple("com.apple.MobileSMS"),
    apple("com.apple.internetAccountsMigrator"),
]

let contactsPreset = AppPreset(
    id: "contacts-data-protection",
    appName: "Contacts",
    appBundlePath: "/System/Applications/Contacts.app",
    description: "Prevents other processes from reading your Contacts database and account data. Only Contacts, its sync agents, and Messages may open files in the Contacts data directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-0004-0001-0001-000000000001")!,
            protectedPathPrefix: "/Users/*/Library/Application Support/AddressBook",
            allowedSignatures: contactsCoreSignatures
        ),
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-0004-0001-0001-000000000002")!,
            protectedPathPrefix: "/Users/*/Library/Containers/com.apple.AddressBook",
            allowedSignatures: [
                apple("com.apple.AddressBook"),
            ]
        ),
    ]
)
