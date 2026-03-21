//
//  ESInboundAdapterTests.swift
//  clearancekitTests
//

import Testing
import Foundation

// MARK: - mutePath

@Suite("mutePath")
struct MutePathTests {
    @Test("literal path unchanged")
    func literalPath() {
        #expect(mutePath(for: "/Library/Application Support/clearancekit") == "/Library/Application Support/clearancekit")
    }

    @Test("stops at first wildcard component")
    func stopsAtWildcard() {
        #expect(mutePath(for: "/Users/*/Documents") == "/Users")
    }

    @Test("double-star stops correctly")
    func doubleStarStops() {
        #expect(mutePath(for: "/a/**/file.txt") == "/a")
    }

    @Test("wildcard at root returns /")
    func wildcardAtRoot() {
        #expect(mutePath(for: "/*") == "/")
    }

    @Test("question mark stops correctly")
    func questionMarkStops() {
        #expect(mutePath(for: "/data/v?/file") == "/data")
    }
}
