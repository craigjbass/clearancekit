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

@Suite("ProcessTree.record")
struct ProcessTreeRecordTests {

    private func record(pid: pid_t, version: UInt32, path: String) -> ProcessRecord {
        ProcessRecord(
            identity: ProcessIdentity(pid: pid, pidVersion: version),
            parentIdentity: ProcessIdentity(pid: 1, pidVersion: 1),
            path: path,
            teamID: "apple",
            signingID: "com.apple.Safari",
            uid: 501,
            gid: 20
        )
    }

    @Test("returns the record of an inserted identity")
    func returnsInsertedRecord() {
        let tree = ProcessTree()
        tree.insert(record(pid: 300, version: 4, path: "/Applications/Safari.app/Contents/MacOS/Safari"))

        let found = tree.record(of: ProcessIdentity(pid: 300, pidVersion: 4))

        #expect(found?.path == "/Applications/Safari.app/Contents/MacOS/Safari")
        #expect(found?.signingID == "com.apple.Safari")
    }

    @Test("returns nil when the identity is not in the tree")
    func returnsNilForAbsentIdentity() {
        let tree = ProcessTree()

        #expect(tree.record(of: ProcessIdentity(pid: 300, pidVersion: 4)) == nil)
    }
}

@Suite("ProcessTree.lifecycle")
struct ProcessTreeLifecycleTests {

    private func record(pid: pid_t, version: UInt32 = 1) -> ProcessRecord {
        ProcessRecord(
            identity: ProcessIdentity(pid: pid, pidVersion: version),
            parentIdentity: ProcessIdentity(pid: 1, pidVersion: 1),
            path: "/bin/sleep",
            teamID: "apple",
            signingID: "com.apple.sleep",
            uid: 501,
            gid: 20
        )
    }

    private func lifecycle(of identity: ProcessIdentity, in tree: ProcessTree) -> ProcessLifecycle? {
        tree.allRecords().first { $0.identity == identity }?.lifecycle
    }

    @Test("an inserted record reports running")
    func insertedRecordIsRunning() {
        let tree = ProcessTree()
        tree.insert(record(pid: 300))

        #expect(lifecycle(of: ProcessIdentity(pid: 300, pidVersion: 1), in: tree) == .running)
    }

    @Test("remove marks the record exited and allRecords still reports it during retention")
    func removeMarksRecordExited() {
        let tree = ProcessTree()
        tree.insert(record(pid: 300))

        tree.remove(identity: ProcessIdentity(pid: 300, pidVersion: 1))

        #expect(lifecycle(of: ProcessIdentity(pid: 300, pidVersion: 1), in: tree) == .exited)
    }

    @Test("remove keeps the exited record available for lookup during retention")
    func exitedRecordStaysAvailableForLookup() {
        let tree = ProcessTree()
        tree.insert(record(pid: 300))

        tree.remove(identity: ProcessIdentity(pid: 300, pidVersion: 1))

        #expect(tree.record(of: ProcessIdentity(pid: 300, pidVersion: 1))?.lifecycle == .exited)
    }

    @Test("remove does not change other records")
    func removeLeavesOtherRecordsRunning() {
        let tree = ProcessTree()
        tree.insert(record(pid: 300))
        tree.insert(record(pid: 400))

        tree.remove(identity: ProcessIdentity(pid: 300, pidVersion: 1))

        #expect(lifecycle(of: ProcessIdentity(pid: 400, pidVersion: 1), in: tree) == .running)
    }

    @Test("a new process that reuses the PID of an exited process reports running")
    func reusedPIDReportsRunning() {
        let tree = ProcessTree()
        tree.insert(record(pid: 300, version: 1))
        tree.remove(identity: ProcessIdentity(pid: 300, pidVersion: 1))

        tree.insert(record(pid: 300, version: 2))

        #expect(lifecycle(of: ProcessIdentity(pid: 300, pidVersion: 2), in: tree) == .running)
    }
}

@Suite("ProcessTree.replaceImage")
struct ProcessTreeReplaceImageTests {

    private let launchd = ProcessIdentity(pid: 1, pidVersion: 1)

    private func record(pid: pid_t, version: UInt32, parent: ProcessIdentity, path: String) -> ProcessRecord {
        ProcessRecord(
            identity: ProcessIdentity(pid: pid, pidVersion: version),
            parentIdentity: parent,
            path: path,
            teamID: "",
            signingID: "",
            uid: 501,
            gid: 20
        )
    }

    @Test("a child keeps the image that created it as ancestor after the parent calls exec")
    func childKeepsCreatingImageAfterParentExec() {
        let tree = ProcessTree()
        let launcher = record(pid: 100, version: 1, parent: launchd, path: "/Users/user/launcher")
        let helper = record(pid: 200, version: 1, parent: launcher.identity, path: "/Users/user/launcher")
        let trusted = record(pid: 100, version: 2, parent: launchd, path: "/Applications/Trusted.app/Contents/MacOS/Trusted")
        let reader = record(pid: 200, version: 2, parent: trusted.identity, path: "/Users/user/Applications/reader")
        tree.insert(launcher)
        tree.insert(helper)
        tree.replaceImage(previousImage: launcher.identity, newImage: trusted)

        tree.replaceImage(previousImage: helper.identity, newImage: reader)

        #expect(tree.ancestors(of: reader.identity).map(\.path) == ["/Users/user/launcher"])
    }

    @Test("the new image keeps the full ancestor chain of the previous image")
    func newImageKeepsAncestorChainOfPreviousImage() {
        let tree = ProcessTree()
        let grandparent = record(pid: 10, version: 1, parent: launchd, path: "/grandparent")
        let parent = record(pid: 100, version: 1, parent: grandparent.identity, path: "/parent")
        let child = record(pid: 200, version: 1, parent: parent.identity, path: "/child")
        let newImage = record(pid: 200, version: 2, parent: parent.identity, path: "/new-image")
        tree.insert(grandparent)
        tree.insert(parent)
        tree.insert(child)

        tree.replaceImage(previousImage: child.identity, newImage: newImage)

        #expect(tree.ancestors(of: newImage.identity).map(\.path) == ["/parent", "/grandparent"])
    }

    @Test("the new image record keeps the parent identity of the previous image")
    func newImageKeepsParentIdentityOfPreviousImage() {
        let tree = ProcessTree()
        let parent = record(pid: 100, version: 1, parent: launchd, path: "/parent")
        let child = record(pid: 200, version: 1, parent: parent.identity, path: "/child")
        let newImage = record(pid: 200, version: 2, parent: ProcessIdentity(pid: 100, pidVersion: 2), path: "/new-image")
        tree.insert(parent)
        tree.insert(child)

        tree.replaceImage(previousImage: child.identity, newImage: newImage)

        #expect(tree.record(of: newImage.identity)?.parentIdentity == parent.identity)
        #expect(tree.record(of: newImage.identity)?.path == "/new-image")
    }

    @Test("the previous image record stays available as exited during retention")
    func previousImageStaysAvailableAsExited() {
        let tree = ProcessTree()
        let child = record(pid: 200, version: 1, parent: launchd, path: "/child")
        let newImage = record(pid: 200, version: 2, parent: launchd, path: "/new-image")
        tree.insert(child)

        tree.replaceImage(previousImage: child.identity, newImage: newImage)

        #expect(tree.record(of: child.identity)?.path == "/child")
        #expect(tree.record(of: child.identity)?.lifecycle == .exited)
        #expect(tree.record(of: newImage.identity)?.lifecycle == .running)
    }

    @Test("the previous image keeps its ancestors during retention")
    func previousImageKeepsAncestorsDuringRetention() {
        let tree = ProcessTree()
        let parent = record(pid: 100, version: 1, parent: launchd, path: "/parent")
        let child = record(pid: 200, version: 1, parent: parent.identity, path: "/child")
        let newImage = record(pid: 200, version: 2, parent: parent.identity, path: "/new-image")
        tree.insert(parent)
        tree.insert(child)

        tree.replaceImage(previousImage: child.identity, newImage: newImage)

        #expect(tree.ancestors(of: child.identity).map(\.path) == ["/parent"])
    }

    @Test("the new image gets no ancestors when the previous image is not in the tree")
    func newImageHasNoAncestorsWhenPreviousImageIsAbsent() {
        let tree = ProcessTree()
        let trusted = record(pid: 100, version: 2, parent: launchd, path: "/Applications/Trusted.app/Contents/MacOS/Trusted")
        let reader = record(pid: 200, version: 2, parent: trusted.identity, path: "/Users/user/Applications/reader")
        tree.insert(trusted)

        tree.replaceImage(previousImage: ProcessIdentity(pid: 200, pidVersion: 1), newImage: reader)

        #expect(tree.ancestors(of: reader.identity).isEmpty)
    }

    @Test("a child forked after the exec gets the new image as ancestor")
    func childForkedAfterExecGetsNewImage() {
        let tree = ProcessTree()
        let launcher = record(pid: 100, version: 1, parent: launchd, path: "/launcher")
        let trusted = record(pid: 100, version: 2, parent: launchd, path: "/Applications/Trusted.app/Contents/MacOS/Trusted")
        let forkedChild = record(pid: 300, version: 1, parent: trusted.identity, path: "/Applications/Trusted.app/Contents/MacOS/Trusted")
        tree.insert(launcher)
        tree.replaceImage(previousImage: launcher.identity, newImage: trusted)

        tree.insert(forkedChild)

        #expect(tree.ancestors(of: forkedChild.identity).map(\.path) == ["/Applications/Trusted.app/Contents/MacOS/Trusted"])
    }
}
