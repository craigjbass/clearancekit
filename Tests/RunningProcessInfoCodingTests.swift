//
//  RunningProcessInfoCodingTests.swift
//  clearancekitTests
//

import Testing
import Foundation

private let runningProcessInfoClasses: [AnyClass] = [RunningProcessInfo.self, NSArray.self, NSString.self]

@Suite("RunningProcessInfo secure coding")
struct RunningProcessInfoCodingTests {

    private func processInfo(lifecycle: ProcessLifecycle) -> RunningProcessInfo {
        RunningProcessInfo(
            pid: 300,
            pidVersion: 4,
            parentPID: 1,
            parentPIDVersion: 1,
            path: "/bin/sleep",
            teamID: "apple",
            signingID: "com.apple.sleep",
            uid: 501,
            gid: 20,
            lifecycle: lifecycle
        )
    }

    private func roundTrip(_ info: RunningProcessInfo) throws -> RunningProcessInfo? {
        let archive = try NSKeyedArchiver.archivedData(withRootObject: info, requiringSecureCoding: true)
        return try NSKeyedUnarchiver.unarchivedObject(ofClasses: runningProcessInfoClasses, from: archive) as? RunningProcessInfo
    }

    @Test("exited lifecycle survives a secure-coding round trip")
    func exitedLifecycleRoundTrips() throws {
        #expect(try roundTrip(processInfo(lifecycle: .exited))?.lifecycle == .exited)
    }

    @Test("running lifecycle survives a secure-coding round trip")
    func runningLifecycleRoundTrips() throws {
        #expect(try roundTrip(processInfo(lifecycle: .running))?.lifecycle == .running)
    }
}
