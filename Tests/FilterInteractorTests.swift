//
//  FilterInteractorTests.swift
//  clearancekitTests
//

import Testing
import Foundation

// MARK: - FakeProcessTree

private final class FakeProcessTree: @unchecked Sendable, ProcessTreeProtocol {
    private(set) var insertedIdentities: [ProcessIdentity] = []
    private(set) var removedIdentities: [ProcessIdentity] = []
    var containsResult = false
    var ancestorsResult: [AncestorInfo] = []

    func insert(_ record: ProcessRecord) {
        insertedIdentities.append(record.identity)
    }

    func remove(identity: ProcessIdentity) {
        removedIdentities.append(identity)
    }

    func contains(identity: ProcessIdentity) -> Bool {
        containsResult
    }

    func ancestors(of identity: ProcessIdentity) -> [AncestorInfo] {
        ancestorsResult
    }
}

// MARK: - FilterInteractorTests

@Suite("FilterInteractor")
struct FilterInteractorTests {

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

    private func openFileEvent(
        path: String,
        processPath: String = "/usr/bin/test",
        teamID: String = "",
        signingID: String = "",
        processIdentity: ProcessIdentity? = nil,
        deadline: UInt64 = 0,
        respond: @escaping @Sendable (Bool) -> Void
    ) -> OpenFileEvent {
        OpenFileEvent(
            path: path,
            processIdentity: processIdentity ?? identity(pid: 100),
            processID: 100,
            parentPID: 1,
            processPath: processPath,
            teamID: teamID,
            signingID: signingID,
            uid: 501,
            gid: 20,
            ttyPath: nil,
            deadline: deadline,
            respond: respond
        )
    }

    @Test("fork event inserts child into process tree")
    func forkInsertsChild() {
        let tree = FakeProcessTree()
        let interactor = FilterInteractor(initialRules: [], initialAllowlist: [], processTree: tree)
        let child = record(pid: 200, parentPID: 100, path: "/usr/bin/child")

        interactor.handle(.fork(child: child))

        #expect(tree.insertedIdentities == [child.identity])
    }

    @Test("exec event inserts new image into process tree")
    func execInsertsNewImage() {
        let tree = FakeProcessTree()
        let interactor = FilterInteractor(initialRules: [], initialAllowlist: [], processTree: tree)
        let newImage = record(pid: 200, parentPID: 100, path: "/usr/bin/shell")

        interactor.handle(.exec(newImage: newImage))

        #expect(tree.insertedIdentities == [newImage.identity])
    }

    @Test("exit event removes identity from process tree")
    func exitRemovesIdentity() {
        let tree = FakeProcessTree()
        let interactor = FilterInteractor(initialRules: [], initialAllowlist: [], processTree: tree)
        let processIdentity = identity(pid: 200)

        interactor.handle(.exit(identity: processIdentity))

        #expect(tree.removedIdentities == [processIdentity])
    }

    @Test("openFile with no matching rule allows access without consulting tree")
    func openFileNoRuleAllows() {
        let tree = FakeProcessTree()
        let interactor = FilterInteractor(initialRules: [], initialAllowlist: [], processTree: tree)
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(path: "/tmp/file.txt") { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.openFile(event))
        semaphore.wait()

        #expect(allowed == true)
        #expect(tree.insertedIdentities.isEmpty)
        #expect(tree.removedIdentities.isEmpty)
    }

    @Test("openFile allowed by process signature without consulting tree for ancestry")
    func openFileAllowedBySignature() {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let tree = FakeProcessTree()
        let interactor = FilterInteractor(initialRules: [rule], initialAllowlist: [], processTree: tree)
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(
            path: "/protected/data.db",
            teamID: "TEAM1",
            signingID: "com.example.app"
        ) { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.openFile(event))
        semaphore.wait()

        #expect(allowed == true)
    }

    @Test("openFile denied when process signature does not match")
    func openFileDeniedBySignatureMismatch() {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let tree = FakeProcessTree()
        let interactor = FilterInteractor(initialRules: [rule], initialAllowlist: [], processTree: tree)
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(
            path: "/protected/data.db",
            teamID: "OTHER",
            signingID: "com.other.app"
        ) { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.openFile(event))
        semaphore.wait()

        #expect(allowed == false)
    }

    @Test("openFile allowed when ancestor matches allowed ancestor path")
    func openFileAllowedByAncestorPath() {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedAncestorProcessPaths: ["/usr/bin/terminal"]
        )
        let tree = FakeProcessTree()
        tree.containsResult = true
        tree.ancestorsResult = [AncestorInfo(path: "/usr/bin/terminal", teamID: "", signingID: "")]
        let interactor = FilterInteractor(initialRules: [rule], initialAllowlist: [], processTree: tree)
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(path: "/protected/file.txt") { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.openFile(event))
        semaphore.wait()

        #expect(allowed == true)
    }

    @Test("openFile denied when process is not found in tree before deadline")
    func openFileDeniedWhenProcessNotInTree() {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedAncestorProcessPaths: ["/usr/bin/terminal"]
        )
        let tree = FakeProcessTree()
        tree.containsResult = false
        let interactor = FilterInteractor(initialRules: [rule], initialAllowlist: [], processTree: tree)
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        // deadline = 0 ensures waitForProcess exits immediately without spinning
        let event = openFileEvent(path: "/protected/file.txt", deadline: 0) { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.openFile(event))
        semaphore.wait()

        #expect(allowed == false)
    }

    @Test("openFile denied when ancestor path does not match allowed ancestor")
    func openFileDeniedWhenAncestorPathMismatches() {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedAncestorProcessPaths: ["/usr/bin/terminal"]
        )
        let tree = FakeProcessTree()
        tree.containsResult = true
        tree.ancestorsResult = [AncestorInfo(path: "/usr/bin/other", teamID: "", signingID: "")]
        let interactor = FilterInteractor(initialRules: [rule], initialAllowlist: [], processTree: tree)
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(path: "/protected/file.txt") { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.openFile(event))
        semaphore.wait()

        #expect(allowed == false)
    }

    @Test("globally allowlisted process bypasses all rules")
    func globallyAllowlistedProcessAllowed() {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let allowlistEntry = AllowlistEntry(signingID: "com.example.allowlisted", teamID: "ALLOWLISTED")
        let tree = FakeProcessTree()
        let interactor = FilterInteractor(initialRules: [rule], initialAllowlist: [allowlistEntry], processTree: tree)
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(
            path: "/protected/data.db",
            teamID: "ALLOWLISTED",
            signingID: "com.example.allowlisted"
        ) { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.openFile(event))
        semaphore.wait()

        #expect(allowed == true)
    }
}
