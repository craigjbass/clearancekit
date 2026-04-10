//
//  FAAFilterInteractorTests.swift
//  clearancekitTests
//

import Testing
import Foundation

// MARK: - Helpers

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

    func allRecords() -> [ProcessRecord] { [] }
}

private func makeFAAInteractor(
    rules: [FAARule] = [],
    allowlist: [AllowlistEntry] = [],
    ancestorAllowlist: [AncestorAllowlistEntry] = [],
    processTree: ProcessTreeProtocol,
    processTreeQueue: DispatchQueue = DispatchQueue(label: "test.process-tree")
) -> FAAFilterInteractor {
    let allowlistState = AllowlistState(initialAllowlist: allowlist, initialAncestorAllowlist: ancestorAllowlist)
    let postRespondHandler = PostRespondHandler()
    let ref = WeakBox<FAAFilterInteractor>()
    let pipeline = FileAuthPipeline(
        processTree: processTree,
        rulesProvider: { ref.value?.currentRules() ?? [] },
        allowlistProvider: { allowlistState.currentAllowlist() },
        ancestorAllowlistProvider: { allowlistState.currentAncestorAllowlist() },
        postRespond: { _, _, _, _ in }
    )
    let interactor = FAAFilterInteractor(
        initialRules: rules,
        allowlistState: allowlistState,
        processTree: processTree,
        pipeline: pipeline,
        processTreeQueue: processTreeQueue,
        postRespondHandler: postRespondHandler
    )
    ref.value = interactor
    pipeline.start()
    return interactor
}

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
    accessKind: AccessKind = .write,
    processIdentity: ProcessIdentity? = nil,
    deadline: UInt64 = 0,
    respond: @escaping @Sendable (Bool) -> Void
) -> FileAuthEvent {
    FileAuthEvent(
        correlationID: UUID(),
        operation: .open,
        accessKind: accessKind,
        path: path,
        secondaryPath: nil,
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
        respond: { allowed, _ in respond(allowed) }
    )
}

private func openFileEventCapturingCache(
    path: String,
    teamID: String = "",
    signingID: String = "",
    accessKind: AccessKind = .write,
    respond: @escaping @Sendable (Bool, Bool) -> Void
) -> FileAuthEvent {
    FileAuthEvent(
        correlationID: UUID(),
        operation: .open,
        accessKind: accessKind,
        path: path,
        secondaryPath: nil,
        processIdentity: identity(pid: 100),
        processID: 100,
        parentPID: 1,
        processPath: "/usr/bin/test",
        teamID: teamID,
        signingID: signingID,
        uid: 501,
        gid: 20,
        ttyPath: nil,
        deadline: 0,
        respond: respond
    )
}

// MARK: - FAAFilterInteractorTests

@Suite("FAAFilterInteractor")
struct FAAFilterInteractorTests {

    // MARK: - Process tree lifecycle

    @Test("fork event inserts child into process tree")
    func forkInsertsChild() {
        let tree = FakeProcessTree()
        let queue = DispatchQueue(label: "test.process-tree")
        let interactor = makeFAAInteractor(processTree: tree, processTreeQueue: queue)
        let child = record(pid: 200, parentPID: 100, path: "/usr/bin/child")

        interactor.handleFork(child: child)
        queue.sync {}

        #expect(tree.insertedIdentities == [child.identity])
    }

    @Test("exec event inserts new image into process tree")
    func execInsertsNewImage() {
        let tree = FakeProcessTree()
        let queue = DispatchQueue(label: "test.process-tree")
        let interactor = makeFAAInteractor(processTree: tree, processTreeQueue: queue)
        let newImage = record(pid: 200, parentPID: 100, path: "/usr/bin/shell")

        interactor.handleExec(newImage: newImage)
        queue.sync {}

        #expect(tree.insertedIdentities == [newImage.identity])
    }

    @Test("exit event removes identity from process tree")
    func exitRemovesIdentity() {
        let tree = FakeProcessTree()
        let queue = DispatchQueue(label: "test.process-tree")
        let interactor = makeFAAInteractor(processTree: tree, processTreeQueue: queue)
        let processIdentity = identity(pid: 200)

        interactor.handleExit(identity: processIdentity)
        queue.sync {}

        #expect(tree.removedIdentities == [processIdentity])
    }

    // MARK: - FAA decisions

    @Test("openFile with no matching rule allows access")
    func openFileNoRuleAllows() async {
        let tree = FakeProcessTree()
        let interactor = makeFAAInteractor(processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(path: "/tmp/file.txt") { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }

    @Test("openFile allowed by process signature")
    func openFileAllowedBySignature() async {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let tree = FakeProcessTree()
        let interactor = makeFAAInteractor(rules: [rule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/protected/data.db",
                teamID: "TEAM1",
                signingID: "com.example.app"
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }

    @Test("openFile denied when signature does not match")
    func openFileDeniedBySignatureMismatch() async {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let tree = FakeProcessTree()
        let interactor = makeFAAInteractor(rules: [rule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/protected/data.db",
                teamID: "OTHER",
                signingID: "com.other.app"
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == false)
    }

    @Test("openFile allowed when ancestor matches allowed ancestor path")
    func openFileAllowedByAncestorPath() async {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedAncestorProcessPaths: ["/usr/bin/terminal"]
        )
        let tree = FakeProcessTree()
        tree.containsResult = true
        tree.ancestorsResult = [AncestorInfo(path: "/usr/bin/terminal", teamID: "", signingID: "")]
        let interactor = makeFAAInteractor(rules: [rule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(path: "/protected/file.txt") { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }

    @Test("openFile denied when process is not found in tree before deadline")
    func openFileDeniedWhenProcessNotInTree() async {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedAncestorProcessPaths: ["/usr/bin/terminal"]
        )
        let tree = FakeProcessTree()
        tree.containsResult = false
        let interactor = makeFAAInteractor(rules: [rule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(path: "/protected/file.txt", deadline: 0) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == false)
    }

    @Test("openFile denied when ancestor path does not match")
    func openFileDeniedWhenAncestorPathMismatches() async {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedAncestorProcessPaths: ["/usr/bin/terminal"]
        )
        let tree = FakeProcessTree()
        tree.containsResult = true
        tree.ancestorsResult = [AncestorInfo(path: "/usr/bin/other", teamID: "", signingID: "")]
        let interactor = makeFAAInteractor(rules: [rule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(path: "/protected/file.txt") { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == false)
    }

    @Test("globally allowlisted process bypasses all rules")
    func globallyAllowlistedProcessAllowed() async {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let allowlistEntry = AllowlistEntry(signingID: "com.example.allowlisted", teamID: "ALLOWLISTED")
        let tree = FakeProcessTree()
        let interactor = makeFAAInteractor(rules: [rule], allowlist: [allowlistEntry], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/protected/data.db",
                teamID: "ALLOWLISTED",
                signingID: "com.example.allowlisted"
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }

    @Test("globally allowlisted process responds with cache enabled")
    func globallyAllowlistedProcessCaches() async {
        let allowlistEntry = AllowlistEntry(signingID: "com.example.allowlisted", teamID: "ALLOWLISTED")
        let tree = FakeProcessTree()
        let interactor = makeFAAInteractor(allowlist: [allowlistEntry], processTree: tree)

        let cached: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEventCapturingCache(
                path: "/any/path",
                teamID: "ALLOWLISTED",
                signingID: "com.example.allowlisted"
            ) { _, cache in
                continuation.resume(returning: cache)
            })
        }

        #expect(cached == true)
    }

    @Test("process allowed when ancestor matches ancestor allowlist entry")
    func ancestorAllowlistBypasses() async {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let ancestorEntry = AncestorAllowlistEntry(processPath: "/usr/bin/trusted-shell")
        let tree = FakeProcessTree()
        tree.containsResult = true
        tree.ancestorsResult = [AncestorInfo(path: "/usr/bin/trusted-shell", teamID: "", signingID: "")]
        let interactor = makeFAAInteractor(rules: [rule], ancestorAllowlist: [ancestorEntry], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/protected/data.db",
                teamID: "UNRELATED",
                signingID: "com.unrelated.app"
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }

    @Test("process denied when ancestor does not match ancestor allowlist")
    func ancestorAllowlistMismatchDenied() async {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let ancestorEntry = AncestorAllowlistEntry(processPath: "/usr/bin/trusted-shell")
        let tree = FakeProcessTree()
        tree.containsResult = true
        tree.ancestorsResult = [AncestorInfo(path: "/usr/bin/evil-shell", teamID: "", signingID: "")]
        let interactor = makeFAAInteractor(rules: [rule], ancestorAllowlist: [ancestorEntry], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/protected/data.db",
                teamID: "UNRELATED",
                signingID: "com.unrelated.app"
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == false)
    }

    @Test("process path match skips ancestry lookup even with an expired deadline")
    func processPathMatchSkipsAncestryLookup() async {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedProcessPaths: ["/usr/bin/safe"],
            allowedAncestorProcessPaths: ["/usr/bin/terminal"]
        )
        let tree = FakeProcessTree()
        tree.containsResult = false
        let interactor = makeFAAInteractor(rules: [rule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/protected/file.txt",
                processPath: "/usr/bin/safe",
                deadline: 0
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }
}
