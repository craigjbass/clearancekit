//
//  ProcessTreeTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("ProcessTree.ancestors")
struct ProcessTreeAncestorsTests {

    private func identity(pid: pid_t, version: UInt32 = 1) -> ProcessIdentity {
        ProcessIdentity(pid: pid, pidVersion: version)
    }

    private func record(pid: pid_t, parentPID: pid_t, path: String) -> ProcessRecord {
        ProcessRecord(
            identity: identity(pid: pid),
            parentIdentity: identity(pid: parentPID),
            path: path,
            teamID: "",
            signingID: "",
            uid: 0,
            gid: 0
        )
    }

    private func makeTree(_ records: ProcessRecord...) -> ProcessTree {
        let tree = ProcessTree()
        for r in records { tree.insert(r) }
        return tree
    }

    @Test("returns empty when identity is not in tree")
    func pidNotInTree() {
        let tree = ProcessTree()
        #expect(tree.ancestors(of: identity(pid: 999)).isEmpty)
    }

    @Test("returns empty when parent is absent from tree")
    func parentAbsentFromTree() {
        let tree = makeTree(
            record(pid: 200, parentPID: 100, path: "/child")
        )
        #expect(tree.ancestors(of: identity(pid: 200)).isEmpty)
    }

    @Test("returns immediate parent for two-level ancestry")
    func twoLevelAncestry() {
        let tree = makeTree(
            record(pid: 100, parentPID: 1, path: "/parent"),
            record(pid: 200, parentPID: 100, path: "/child")
        )
        let ancestors = tree.ancestors(of: identity(pid: 200))
        #expect(ancestors.map(\.path) == ["/parent"])
    }

    @Test("returns full chain for multi-level ancestry")
    func multiLevelAncestry() {
        let tree = makeTree(
            record(pid: 10, parentPID: 1, path: "/grandparent"),
            record(pid: 100, parentPID: 10, path: "/parent"),
            record(pid: 200, parentPID: 100, path: "/child")
        )
        let ancestors = tree.ancestors(of: identity(pid: 200))
        #expect(ancestors.map(\.path) == ["/parent", "/grandparent"])
    }

    @Test("immediate child of launchd (PID 1 absent) returns empty")
    func immediateChildOfLaunchdReturnsEmpty() {
        let tree = makeTree(
            record(pid: 200, parentPID: 1, path: "/child")
        )
        #expect(tree.ancestors(of: identity(pid: 200)).isEmpty)
    }

    @Test("stops traversal at gap where parent has exited")
    func stopsAtGapInTree() {
        let tree = makeTree(
            record(pid: 10, parentPID: 1, path: "/grandparent"),
            // pid 100 intentionally absent — simulates a process that exited
            record(pid: 200, parentPID: 100, path: "/child")
        )
        #expect(tree.ancestors(of: identity(pid: 200)).isEmpty)
    }

    @Test("cycle is naturally bounded by insertion order — earlier insert has no parent yet")
    func cycleIsBoundedByInsertionOrder() {
        let tree = makeTree(
            record(pid: 100, parentPID: 200, path: "/a"),
            record(pid: 200, parentPID: 100, path: "/b")
        )
        // pid 100 was inserted first, when pid 200 didn't exist yet — chain is empty.
        #expect(tree.ancestors(of: identity(pid: 100)).isEmpty)
        // pid 200 was inserted second, when pid 100 existed with an empty chain.
        #expect(tree.ancestors(of: identity(pid: 200)).map(\.path) == ["/a"])
    }
}
