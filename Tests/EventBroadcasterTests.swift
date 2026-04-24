//
//  EventBroadcasterTests.swift
//  clearancekitTests
//

import Testing
import Foundation

// MARK: - EventBroadcasterTests

@Suite("EventBroadcaster")
struct EventBroadcasterTests {

    private func makeEvent(path: String = "/test/path") -> FolderOpenEvent {
        FolderOpenEvent(
            path: path,
            timestamp: Date(),
            processID: 100,
            processPath: "/usr/bin/test"
        )
    }

    // MARK: - Client management

    @Test("addClient returns incremented count")
    func addClientReturnsIncrementedCount() {
        let broadcaster = EventBroadcaster()
        let conn = NSXPCConnection()

        let count = broadcaster.addClient(conn)

        #expect(count == 1)
    }

    @Test("addClient twice returns count of two")
    func addClientTwiceReturnsTwoCount() {
        let broadcaster = EventBroadcaster()
        let connA = NSXPCConnection()
        let connB = NSXPCConnection()

        broadcaster.addClient(connA)
        let count = broadcaster.addClient(connB)

        #expect(count == 2)
    }

    @Test("removeClient returns decremented count")
    func removeClientReturnsDecrementedCount() {
        let broadcaster = EventBroadcaster()
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)

        let count = broadcaster.removeClient(conn)

        #expect(count == 0)
    }

    @Test("removing unknown connection leaves count unchanged")
    func removeUnknownConnectionLeavesCountUnchanged() {
        let broadcaster = EventBroadcaster()
        let known = NSXPCConnection()
        let unknown = NSXPCConnection()
        broadcaster.addClient(known)

        let count = broadcaster.removeClient(unknown)

        #expect(count == 1)
    }

    // MARK: - Event history

    @Test("broadcast appends to recent events")
    func broadcastAppendsToRecentEvents() {
        let broadcaster = EventBroadcaster()
        let event = makeEvent()

        broadcaster.broadcast(event)

        #expect(broadcaster.recentEvents().contains { $0.eventID == event.eventID })
    }

    @Test("recentEvents returns empty when no events broadcast")
    func recentEventsEmptyInitially() {
        let broadcaster = EventBroadcaster()

        #expect(broadcaster.recentEvents().isEmpty)
    }

    @Test("history is capped at maxHistoryCount")
    func historyIsCappedAtMaxHistoryCount() {
        let cap = 5
        let broadcaster = EventBroadcaster(maxHistoryCount: cap)

        for _ in 0..<(cap + 3) {
            broadcaster.broadcast(makeEvent())
        }

        #expect(broadcaster.recentEvents().count == cap)
    }

    @Test("history retains most recent events when cap is exceeded")
    func historyRetainsMostRecentEvents() {
        let cap = 3
        let broadcaster = EventBroadcaster(maxHistoryCount: cap)
        var events: [FolderOpenEvent] = []

        for i in 0..<5 {
            let event = makeEvent(path: "/test/\(i)")
            events.append(event)
            broadcaster.broadcast(event)
        }

        let recent = broadcaster.recentEvents()
        #expect(recent.count == cap)
        #expect(recent[0].eventID == events[2].eventID)
        #expect(recent[1].eventID == events[3].eventID)
        #expect(recent[2].eventID == events[4].eventID)
    }

    @Test("broadcast preserves event ordering")
    func broadcastPreservesOrdering() {
        let broadcaster = EventBroadcaster()
        let first = makeEvent(path: "/first")
        let second = makeEvent(path: "/second")

        broadcaster.broadcast(first)
        broadcaster.broadcast(second)

        let recent = broadcaster.recentEvents()
        #expect(recent.count == 2)
        #expect(recent[0].eventID == first.eventID)
        #expect(recent[1].eventID == second.eventID)
    }

    // MARK: - Allow stream subscription

    @Test("beginAllowStream tracks subscribing connection")
    func beginAllowStreamTracksConnection() {
        let broadcaster = EventBroadcaster()
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)

        broadcaster.beginAllowStream(for: conn)

        #expect(broadcaster.allowStreamClientCount == 1)
    }

    @Test("endAllowStream removes subscribing connection")
    func endAllowStreamRemovesConnection() {
        let broadcaster = EventBroadcaster()
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)
        broadcaster.beginAllowStream(for: conn)

        broadcaster.endAllowStream(for: conn)

        #expect(broadcaster.allowStreamClientCount == 0)
    }

    @Test("removeClient also removes from allow stream subscribers")
    func removeClientCleansUpAllowStream() {
        let broadcaster = EventBroadcaster()
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)
        broadcaster.beginAllowStream(for: conn)

        broadcaster.removeClient(conn)

        #expect(broadcaster.allowStreamClientCount == 0)
    }

    // MARK: - Allow event filtering

    @Test("allow events are stored in ring buffer even without subscribers")
    func allowEventsStoredInRingBufferWithoutSubscribers() {
        let broadcaster = EventBroadcaster()
        let event = FolderOpenEvent(
            path: "/test",
            timestamp: Date(),
            processID: 100,
            processPath: "/usr/bin/test",
            accessAllowed: true
        )

        broadcaster.broadcast(event)

        #expect(broadcaster.recentEvents().count == 1)
        #expect(broadcaster.recentEvents()[0].eventID == event.eventID)
    }
}
