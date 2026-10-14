//
//  DenyNotificationThrottle.swift
//  clearancekit
//

import Foundation

enum DenyNotificationDecision {
    case post
    case suppress
}

struct DenyNotificationThrottle {
    private let debounceInterval: TimeInterval
    private var lastPostedAt: Date?

    init(debounceInterval: TimeInterval) {
        self.debounceInterval = debounceInterval
    }

    mutating func evaluate(_ event: FolderOpenEvent, at now: Date) -> DenyNotificationDecision {
        if case .quiet = event.notificationPolicy {
            return .suppress
        }
        if let lastPostedAt, now.timeIntervalSince(lastPostedAt) < debounceInterval {
            return .suppress
        }
        lastPostedAt = now
        return .post
    }
}
