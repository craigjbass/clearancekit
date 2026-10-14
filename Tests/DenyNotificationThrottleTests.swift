//
//  DenyNotificationThrottleTests.swift
//  clearancekitTests
//

import Testing
import Foundation

private let debounceInterval: TimeInterval = 30
private let start = Date(timeIntervalSince1970: 1_000)

private func deniedEvent(_ notificationPolicy: NotificationPolicy) -> FolderOpenEvent {
    FolderOpenEvent(
        path: "/protected/file",
        timestamp: start,
        processID: 100,
        processPath: "/bin/cat",
        accessAllowed: false,
        notificationPolicy: notificationPolicy
    )
}

@Suite("DenyNotificationThrottle")
struct DenyNotificationThrottleTests {
    @Test("first deny posts")
    func firstDenyPosts() {
        var throttle = DenyNotificationThrottle(debounceInterval: debounceInterval)

        let decision = throttle.evaluate(deniedEvent(.notify), at: start)

        #expect(decision == .post)
    }

    @Test("deny inside the debounce window is suppressed")
    func denyInsideWindowIsSuppressed() {
        var throttle = DenyNotificationThrottle(debounceInterval: debounceInterval)
        _ = throttle.evaluate(deniedEvent(.notify), at: start)

        let decision = throttle.evaluate(deniedEvent(.notify), at: start.addingTimeInterval(29))

        #expect(decision == .suppress)
    }

    @Test("deny after the debounce window posts")
    func denyAfterWindowPosts() {
        var throttle = DenyNotificationThrottle(debounceInterval: debounceInterval)
        _ = throttle.evaluate(deniedEvent(.notify), at: start)

        let decision = throttle.evaluate(deniedEvent(.notify), at: start.addingTimeInterval(30))

        #expect(decision == .post)
    }
}
