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

// .serialized prevents thread starvation on low-core CI runners (e.g. 3 cores).
// Each test blocks a cooperative thread on DispatchSemaphore.wait() while waiting
// for a Task spawned by FilterInteractor.handle(.fileAuth) to call respond(). With
// concurrent execution, all pool threads can be blocked simultaneously, deadlocking
/// the spawned Tasks. See: https://github.com/craigjbass/clearancekit/issues/66
@Suite("FilterInteractor", .serialized)
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
    ) -> FileAuthEvent {
        FileAuthEvent(
            operation: .open,
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

        interactor.handle(.fileAuth(event))
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

        interactor.handle(.fileAuth(event))
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

        interactor.handle(.fileAuth(event))
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

        interactor.handle(.fileAuth(event))
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

        interactor.handle(.fileAuth(event))
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

        interactor.handle(.fileAuth(event))
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

        interactor.handle(.fileAuth(event))
        semaphore.wait()

        #expect(allowed == true)
    }

    @Test("process allowed when ancestor matches ancestor allowlist entry")
    func ancestorAllowlistBypasses() {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let ancestorEntry = AncestorAllowlistEntry(processPath: "/usr/bin/trusted-shell")
        let tree = FakeProcessTree()
        tree.containsResult = true
        tree.ancestorsResult = [AncestorInfo(path: "/usr/bin/trusted-shell", teamID: "", signingID: "")]
        let interactor = FilterInteractor(
            initialRules: [rule],
            initialAllowlist: [],
            initialAncestorAllowlist: [ancestorEntry],
            processTree: tree
        )
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(
            path: "/protected/data.db",
            teamID: "UNRELATED",
            signingID: "com.unrelated.app"
        ) { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.fileAuth(event))
        semaphore.wait()

        #expect(allowed == true)
    }

    @Test("process denied when ancestor does not match ancestor allowlist entry")
    func ancestorAllowlistMismatchDenied() {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let ancestorEntry = AncestorAllowlistEntry(processPath: "/usr/bin/trusted-shell")
        let tree = FakeProcessTree()
        tree.containsResult = true
        tree.ancestorsResult = [AncestorInfo(path: "/usr/bin/evil-shell", teamID: "", signingID: "")]
        let interactor = FilterInteractor(
            initialRules: [rule],
            initialAllowlist: [],
            initialAncestorAllowlist: [ancestorEntry],
            processTree: tree
        )
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(
            path: "/protected/data.db",
            teamID: "UNRELATED",
            signingID: "com.unrelated.app"
        ) { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.fileAuth(event))
        semaphore.wait()

        #expect(allowed == false)
    }

    @Test("openFile allowed by process path without consulting tree when rule also has ancestor criteria")
    func openFileProcessPathMatchSkipsAncestryLookup() {
        // Rule has BOTH process-path AND ancestor criteria. When the process path
        // matches, the ancestry provider must not be invoked — so even with an
        // expired deadline (process never in tree), the access is allowed.
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedProcessPaths: ["/usr/bin/safe"],
            allowedAncestorProcessPaths: ["/usr/bin/terminal"]
        )
        let tree = FakeProcessTree()
        tree.containsResult = false  // process not in tree; would trigger deny in old code
        let interactor = FilterInteractor(initialRules: [rule], initialAllowlist: [], processTree: tree)
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(
            path: "/protected/file.txt",
            processPath: "/usr/bin/safe",
            deadline: 0  // immediate deadline — any wait would expire instantly
        ) { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.fileAuth(event))
        semaphore.wait()

        #expect(allowed == true)
    }

    // MARK: - Jail tests

    @Test("jailed process denied when accessing path outside allowed prefixes")
    func jailedProcessDeniedOutsidePrefixes() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed"]
        )
        let tree = FakeProcessTree()
        let interactor = FilterInteractor(initialRules: [], initialAllowlist: [], initialJailRules: [jailRule], processTree: tree)
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(
            path: "/forbidden/file.txt",
            teamID: "TEAM1",
            signingID: "com.example.jailed"
        ) { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.fileAuth(event))
        semaphore.wait()

        #expect(allowed == false)
    }

    @Test("jailed process allowed when accessing path within allowed prefixes")
    func jailedProcessAllowedWithinPrefixes() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed"]
        )
        let tree = FakeProcessTree()
        let interactor = FilterInteractor(initialRules: [], initialAllowlist: [], initialJailRules: [jailRule], processTree: tree)
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(
            path: "/allowed/data.db",
            teamID: "TEAM1",
            signingID: "com.example.jailed"
        ) { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.fileAuth(event))
        semaphore.wait()

        #expect(allowed == true)
    }

    @Test("globally allowlisted process escapes jail")
    func globallyAllowlistedProcessEscapesJail() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed"]
        )
        let allowlistEntry = AllowlistEntry(signingID: "com.example.jailed", teamID: "TEAM1")
        let tree = FakeProcessTree()
        let interactor = FilterInteractor(
            initialRules: [],
            initialAllowlist: [allowlistEntry],
            initialJailRules: [jailRule],
            processTree: tree
        )
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(
            path: "/forbidden/file.txt",
            teamID: "TEAM1",
            signingID: "com.example.jailed"
        ) { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.fileAuth(event))
        semaphore.wait()

        #expect(allowed == true)
    }

    @Test("non-jailed process is unaffected by jail rules")
    func nonJailedProcessUnaffected() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed"]
        )
        let tree = FakeProcessTree()
        let interactor = FilterInteractor(initialRules: [], initialAllowlist: [], initialJailRules: [jailRule], processTree: tree)
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(
            path: "/forbidden/file.txt",
            teamID: "OTHER",
            signingID: "com.other.app"
        ) { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.fileAuth(event))
        semaphore.wait()

        #expect(allowed == true)
    }

    @Test("jail check runs before FAA rule evaluation")
    func jailCheckRunsBeforeFAA() {
        // FAA rule would allow this process, but jail rule should deny it first
        let faaRule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed")]
        )
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/other"]
        )
        let tree = FakeProcessTree()
        let interactor = FilterInteractor(
            initialRules: [faaRule],
            initialAllowlist: [],
            initialJailRules: [jailRule],
            processTree: tree
        )
        let semaphore = DispatchSemaphore(value: 0)
        var allowed: Bool?

        let event = openFileEvent(
            path: "/protected/data.db",
            teamID: "TEAM1",
            signingID: "com.example.jailed"
        ) { result in
            allowed = result
            semaphore.signal()
        }

        interactor.handle(.fileAuth(event))
        semaphore.wait()

        #expect(allowed == false)
    }
}
