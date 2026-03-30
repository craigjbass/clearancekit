//
//  Notes.swift
//  clearancekit
//

import Foundation

let notesPreset = AppPreset(
    id: "notes-data-protection",
    appName: "Notes",
    appBundlePath: "/System/Applications/Notes.app",
    description: "Prevents other processes from reading your Notes database and attachments. Only Notes and its extensions may open files in the Notes group container.",
    rules: [
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-0002-0001-0001-000000000001")!,
            protectedPathPrefix: "/Users/*/Library/Group Containers/group.com.apple.notes",
            allowedSignatures: [
                apple("com.apple.Notes"),
                apple("com.apple.Notes.WidgetExtension"),
                apple("com.apple.Notes.QuickLookExtension"),
                apple("com.apple.Notes.SharingExtension"),
                apple("com.apple.Notes.SpotlightIndexExtension"),
                apple("com.apple.Notes.IntentsExtension"),
                apple("com.apple.LinkedNotesUIService"),
                apple("com.apple.accountsd"),
                apple("com.apple.PaperKit.extension.ui"),
            ]
        ),
    ]
)
