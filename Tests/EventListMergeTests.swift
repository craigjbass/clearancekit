//
//  EventListMergeTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("EventListMerge")
struct EventListMergeTests {

    private func makeEvent() -> FolderOpenEvent {
        FolderOpenEvent(path: "/test", timestamp: Date(), processID: 1, processPath: "/p", notificationPolicy: .notify)
    }

    @Test("a re-delivered event is not added twice")
    func redeliveredEventNotAddedTwice() {
        let existing = makeEvent()

        let merged = EventListMerge.prepending(incoming: [existing], to: [existing])

        #expect(merged.map(\.eventID) == [existing.eventID])
    }

    @Test("a new event is added at the front")
    func newEventAddedAtFront() {
        let existing = makeEvent()
        let incoming = makeEvent()

        let merged = EventListMerge.prepending(incoming: [incoming], to: [existing])

        #expect(merged.map(\.eventID) == [incoming.eventID, existing.eventID])
    }

    @Test("incoming events arrive oldest-first and end up newest-first")
    func incomingOrderReversed() {
        let older = makeEvent()
        let newer = makeEvent()

        let merged = EventListMerge.prepending(incoming: [older, newer], to: [])

        #expect(merged.map(\.eventID) == [newer.eventID, older.eventID])
    }

    @Test("an event repeated within the incoming batch is added once")
    func repeatedIncomingEventAddedOnce() {
        let event = makeEvent()

        let merged = EventListMerge.prepending(incoming: [event, event], to: [])

        #expect(merged.count == 1)
    }

    @Test("existing order is preserved")
    func existingOrderPreserved() {
        let first = makeEvent()
        let second = makeEvent()
        let incoming = makeEvent()

        let merged = EventListMerge.prepending(incoming: [incoming], to: [first, second])

        #expect(merged.map(\.eventID) == [incoming.eventID, first.eventID, second.eventID])
    }
}
