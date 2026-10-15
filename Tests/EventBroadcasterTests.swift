//
//  EventBroadcasterTests.swift
//  clearancekitTests
//

import Testing
import Foundation
import os

// MARK: - EventBroadcasterTests

@Suite("EventBroadcaster")
struct EventBroadcasterTests {

    private final class FakeDeliveryRecorder: @unchecked Sendable {
        private let deliveries = OSAllocatedUnfairLock(initialState: [(connection: ObjectIdentifier, eventID: UUID)]())

        var deliver: @Sendable (NSXPCConnection, FolderOpenEvent) -> Void {
            { [self] connection, event in
                deliveries.withLock { $0.append((ObjectIdentifier(connection), event.eventID)) }
            }
        }

        func eventIDs(deliveredTo connection: NSXPCConnection) -> [UUID] {
            deliveries.withLock { $0.filter { $0.connection == ObjectIdentifier(connection) }.map(\.eventID) }
        }
    }

    private func makeQuietDeny(path: String = "/quiet", timestamp: Date = Date()) -> FolderOpenEvent {
        FolderOpenEvent(path: path, timestamp: timestamp, processID: 200, processPath: "/usr/bin/mdworker", accessAllowed: false, notificationPolicy: .quiet)
    }

    private func makeNotifyDeny(path: String = "/notify", timestamp: Date = Date()) -> FolderOpenEvent {
        FolderOpenEvent(path: path, timestamp: timestamp, processID: 300, processPath: "/usr/bin/test", accessAllowed: false, notificationPolicy: .notify)
    }

    private func makeEvent(path: String = "/test/path") -> FolderOpenEvent {
        FolderOpenEvent(
            path: path,
            timestamp: Date(),
            processID: 100,
            processPath: "/usr/bin/test",
            notificationPolicy: .notify
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

        #expect(broadcaster.recentEvents(for: NSXPCConnection()).contains { $0.eventID == event.eventID })
    }

    @Test("recentEvents returns empty when no events broadcast")
    func recentEventsEmptyInitially() {
        let broadcaster = EventBroadcaster()

        #expect(broadcaster.recentEvents(for: NSXPCConnection()).isEmpty)
    }

    @Test("history is capped at maxHistoryCount")
    func historyIsCappedAtMaxHistoryCount() {
        let cap = 5
        let broadcaster = EventBroadcaster(maxHistoryCount: cap)

        for _ in 0..<(cap + 3) {
            broadcaster.broadcast(makeEvent())
        }

        #expect(broadcaster.recentEvents(for: NSXPCConnection()).count == cap)
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

        let recent = broadcaster.recentEvents(for: NSXPCConnection())
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

        let recent = broadcaster.recentEvents(for: NSXPCConnection())
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

    @Test("beginAllowStream returns allow-only events from ring buffer newest-first")
    func beginAllowStreamReturnsBackfill() {
        let broadcaster = EventBroadcaster()
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)

        let deny = FolderOpenEvent(path: "/deny", timestamp: Date(timeIntervalSince1970: 1), processID: 1, processPath: "/p", accessAllowed: false, notificationPolicy: .notify)
        let allowOld = FolderOpenEvent(path: "/old", timestamp: Date(timeIntervalSince1970: 2), processID: 2, processPath: "/p", accessAllowed: true, notificationPolicy: .notify)
        let allowNew = FolderOpenEvent(path: "/new", timestamp: Date(timeIntervalSince1970: 3), processID: 3, processPath: "/p", accessAllowed: true, notificationPolicy: .notify)

        broadcaster.broadcast(deny)
        broadcaster.broadcast(allowOld)
        broadcaster.broadcast(allowNew)

        let backfill = broadcaster.beginAllowStream(for: conn)

        #expect(backfill.count == 2)
        #expect(backfill[0].eventID == allowNew.eventID)
        #expect(backfill[1].eventID == allowOld.eventID)
    }

    @Test("allow events are stored in ring buffer even without subscribers")
    func allowEventsStoredInRingBufferWithoutSubscribers() {
        let broadcaster = EventBroadcaster()
        let event = FolderOpenEvent(
            path: "/test",
            timestamp: Date(),
            processID: 100,
            processPath: "/usr/bin/test",
            accessAllowed: true,
            notificationPolicy: .notify
        )

        broadcaster.broadcast(event)

        #expect(broadcaster.recentEvents(for: NSXPCConnection()).count == 1)
        #expect(broadcaster.recentEvents(for: NSXPCConnection())[0].eventID == event.eventID)
    }

    // MARK: - Quiet stream

    @Test("quiet deny is not delivered to a client that has not begun the quiet stream")
    func quietDenyNotDeliveredWithoutSubscription() {
        let recorder = FakeDeliveryRecorder()
        let broadcaster = EventBroadcaster(deliverFolderOpened: recorder.deliver)
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)

        broadcaster.broadcast(makeQuietDeny())

        #expect(recorder.eventIDs(deliveredTo: conn).isEmpty)
    }

    @Test("quiet deny is delivered to a client that has begun the quiet stream")
    func quietDenyDeliveredToSubscribedClient() {
        let recorder = FakeDeliveryRecorder()
        let broadcaster = EventBroadcaster(deliverFolderOpened: recorder.deliver)
        let subscribed = NSXPCConnection()
        let unsubscribed = NSXPCConnection()
        broadcaster.addClient(subscribed)
        broadcaster.addClient(unsubscribed)
        broadcaster.beginQuietStream(for: subscribed)
        let event = makeQuietDeny()

        broadcaster.broadcast(event)

        #expect(recorder.eventIDs(deliveredTo: subscribed) == [event.eventID])
        #expect(recorder.eventIDs(deliveredTo: unsubscribed).isEmpty)
    }

    @Test("non-quiet deny is delivered to every client")
    func notifyDenyDeliveredToEveryClient() {
        let recorder = FakeDeliveryRecorder()
        let broadcaster = EventBroadcaster(deliverFolderOpened: recorder.deliver)
        let subscribed = NSXPCConnection()
        let unsubscribed = NSXPCConnection()
        broadcaster.addClient(subscribed)
        broadcaster.addClient(unsubscribed)
        broadcaster.beginQuietStream(for: subscribed)
        let event = makeNotifyDeny()

        broadcaster.broadcast(event)

        #expect(recorder.eventIDs(deliveredTo: subscribed) == [event.eventID])
        #expect(recorder.eventIDs(deliveredTo: unsubscribed) == [event.eventID])
    }

    @Test("beginQuietStream returns recent quiet denies newest-first and no other events")
    func beginQuietStreamReturnsQuietDenyBackfill() {
        let broadcaster = EventBroadcaster()
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)
        let quietOld = makeQuietDeny(path: "/old", timestamp: Date(timeIntervalSince1970: 1))
        let notifyDeny = makeNotifyDeny(timestamp: Date(timeIntervalSince1970: 2))
        let allow = makeEvent()
        let quietNew = makeQuietDeny(path: "/new", timestamp: Date(timeIntervalSince1970: 3))
        for event in [quietOld, notifyDeny, allow, quietNew] {
            broadcaster.broadcast(event)
        }

        let backfill = broadcaster.beginQuietStream(for: conn)

        #expect(backfill.map(\.eventID) == [quietNew.eventID, quietOld.eventID])
    }

    @Test("quiet deny stops being delivered after endQuietStream")
    func quietDenyNotDeliveredAfterEndQuietStream() {
        let recorder = FakeDeliveryRecorder()
        let broadcaster = EventBroadcaster(deliverFolderOpened: recorder.deliver)
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)
        broadcaster.beginQuietStream(for: conn)
        broadcaster.endQuietStream(for: conn)

        broadcaster.broadcast(makeQuietDeny())

        #expect(recorder.eventIDs(deliveredTo: conn).isEmpty)
    }

    @Test("removeClient also removes from quiet stream subscribers")
    func removeClientCleansUpQuietStream() {
        let recorder = FakeDeliveryRecorder()
        let broadcaster = EventBroadcaster(deliverFolderOpened: recorder.deliver)
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)
        broadcaster.beginQuietStream(for: conn)
        broadcaster.removeClient(conn)
        broadcaster.addClient(conn)

        broadcaster.broadcast(makeQuietDeny())

        #expect(recorder.eventIDs(deliveredTo: conn).isEmpty)
    }

    @Test("quiet deny is stored in history even without subscribers")
    func quietDenyStoredInHistoryWithoutSubscribers() {
        let broadcaster = EventBroadcaster()
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)
        let event = makeQuietDeny()

        broadcaster.broadcast(event)

        #expect(broadcaster.beginQuietStream(for: conn).map(\.eventID) == [event.eventID])
    }

    @Test("recentEvents(for:) excludes quiet denies for an unsubscribed connection")
    func recentEventsExcludesQuietDenyForUnsubscribedConnection() {
        let broadcaster = EventBroadcaster()
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)
        let notifyDeny = makeNotifyDeny()
        broadcaster.broadcast(makeQuietDeny())
        broadcaster.broadcast(notifyDeny)

        #expect(broadcaster.recentEvents(for: conn).map(\.eventID) == [notifyDeny.eventID])
    }

    @Test("recentEvents(for:) includes quiet denies for a subscribed connection")
    func recentEventsIncludesQuietDenyForSubscribedConnection() {
        let broadcaster = EventBroadcaster()
        let conn = NSXPCConnection()
        broadcaster.addClient(conn)
        broadcaster.beginQuietStream(for: conn)
        let quietDeny = makeQuietDeny()
        let notifyDeny = makeNotifyDeny()
        broadcaster.broadcast(quietDeny)
        broadcaster.broadcast(notifyDeny)

        #expect(broadcaster.recentEvents(for: conn).map(\.eventID) == [quietDeny.eventID, notifyDeny.eventID])
    }
}
