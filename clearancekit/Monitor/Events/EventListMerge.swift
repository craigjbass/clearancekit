//
//  EventListMerge.swift
//  clearancekit
//

import Foundation

enum EventListMerge {
    static func prepending(incoming: [FolderOpenEvent], to existing: [FolderOpenEvent]) -> [FolderOpenEvent] {
        var knownIDs = Set(existing.map(\.eventID))
        var fresh: [FolderOpenEvent] = []
        for event in incoming where knownIDs.insert(event.eventID).inserted {
            fresh.append(event)
        }
        return fresh.reversed() + existing
    }
}
