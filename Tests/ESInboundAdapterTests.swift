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

    @Test("literal pattern selects its prefix and each literal parent")
    func literalPatternSelectsPrefixAndParents() {
        #expect(muteTargets(for: "/Users/develop/goal/*") == [
            MuteTarget(path: "/Users/develop/goal", kind: .prefix),
            MuteTarget(path: "/Users/develop", kind: .literal),
            MuteTarget(path: "/Users", kind: .literal),
            MuteTarget(path: "/", kind: .literal),
        ])
    }

    @Test("wildcard pattern selects its literal prefix and the parents above it")
    func wildcardPatternSelectsPrefixAndParents() {
        #expect(muteTargets(for: "/Users/*/Library/Mail") == [
            MuteTarget(path: "/Users", kind: .prefix),
            MuteTarget(path: "/", kind: .literal),
        ])
    }

    @Test("root pattern selects only the root prefix")
    func rootPatternSelectsOnlyRootPrefix() {
        #expect(muteTargets(for: "/*") == [MuteTarget(path: "/", kind: .prefix)])
    }

    @Test("rules share parent targets")
    func rulesShareParentTargets() {
        let rules = [
            FAARule(protectedPathPrefix: "/Users/*/Library/Mail"),
            FAARule(protectedPathPrefix: "/Users/*/.ssh"),
        ]
        #expect(muteTargets(for: rules) == [
            MuteTarget(path: "/Users", kind: .prefix),
            MuteTarget(path: "/", kind: .literal),
        ])
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
