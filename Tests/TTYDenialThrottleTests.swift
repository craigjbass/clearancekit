//
//  TTYDenialThrottleTests.swift
//  clearancekitTests
//

import Testing
import Foundation

private let debounceInterval: TimeInterval = 2
private let start = Date(timeIntervalSince1970: 1_000)
private let protectedPath = "/Users/user/foo"
private let listingProcess = ProcessIdentity(pid: 100, pidVersion: 1)

@Suite("TTYDenialThrottle")
struct TTYDenialThrottleTests {
    @Test("first denial writes")
    func firstDenialWrites() {
        var throttle = TTYDenialThrottle(debounceInterval: debounceInterval)

        let decision = throttle.evaluate(process: listingProcess, path: protectedPath, at: start)

        #expect(decision == .write)
    }

    @Test("same process and path inside the debounce window is suppressed")
    func sameProcessAndPathInsideWindowIsSuppressed() {
        var throttle = TTYDenialThrottle(debounceInterval: debounceInterval)
        _ = throttle.evaluate(process: listingProcess, path: protectedPath, at: start)

        let decision = throttle.evaluate(process: listingProcess, path: protectedPath, at: start.addingTimeInterval(1))

        #expect(decision == .suppress)
    }

    @Test("same process and path after the debounce window writes")
    func sameProcessAndPathAfterWindowWrites() {
        var throttle = TTYDenialThrottle(debounceInterval: debounceInterval)
        _ = throttle.evaluate(process: listingProcess, path: protectedPath, at: start)

        let decision = throttle.evaluate(process: listingProcess, path: protectedPath, at: start.addingTimeInterval(2))

        #expect(decision == .write)
    }

    @Test("suppressed denials do not extend the debounce window")
    func suppressedDenialsDoNotExtendWindow() {
        var throttle = TTYDenialThrottle(debounceInterval: debounceInterval)
        _ = throttle.evaluate(process: listingProcess, path: protectedPath, at: start)
        _ = throttle.evaluate(process: listingProcess, path: protectedPath, at: start.addingTimeInterval(1.5))

        let decision = throttle.evaluate(process: listingProcess, path: protectedPath, at: start.addingTimeInterval(2))

        #expect(decision == .write)
    }

    @Test("same process with another path writes")
    func sameProcessWithAnotherPathWrites() {
        var throttle = TTYDenialThrottle(debounceInterval: debounceInterval)
        _ = throttle.evaluate(process: listingProcess, path: protectedPath, at: start)

        let decision = throttle.evaluate(process: listingProcess, path: "/Users/user/bar", at: start.addingTimeInterval(1))

        #expect(decision == .write)
    }

    @Test("reused pid with a new pid version writes")
    func reusedPidWithNewVersionWrites() {
        var throttle = TTYDenialThrottle(debounceInterval: debounceInterval)
        _ = throttle.evaluate(process: listingProcess, path: protectedPath, at: start)

        let reusedPid = ProcessIdentity(pid: listingProcess.pid, pidVersion: listingProcess.pidVersion + 1)
        let decision = throttle.evaluate(process: reusedPid, path: protectedPath, at: start.addingTimeInterval(1))

        #expect(decision == .write)
    }
}
