//
//  TTYDenialThrottle.swift
//  opfilter
//

import Foundation

enum TTYDenialDecision {
    case write
    case suppress
}

struct TTYDenialThrottle {
    private struct DenialKey: Hashable {
        let process: ProcessIdentity
        let path: String
    }

    private let debounceInterval: TimeInterval
    private var lastWrittenAt: [DenialKey: Date] = [:]

    init(debounceInterval: TimeInterval) {
        self.debounceInterval = debounceInterval
    }

    mutating func evaluate(process: ProcessIdentity, path: String, at now: Date) -> TTYDenialDecision {
        removeExpiredEntries(at: now)
        let key = DenialKey(process: process, path: path)
        guard lastWrittenAt[key] == nil else { return .suppress }
        lastWrittenAt[key] = now
        return .write
    }

    private mutating func removeExpiredEntries(at now: Date) {
        lastWrittenAt = lastWrittenAt.filter { now.timeIntervalSince($0.value) < debounceInterval }
    }
}
