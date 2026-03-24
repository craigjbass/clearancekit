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

private func makeInteractor(
    rules: [FAARule] = [],
    allowlist: [AllowlistEntry] = [],
    ancestorAllowlist: [AncestorAllowlistEntry] = [],
    jailRules: [JailRule] = [],
    processTree: ProcessTreeProtocol,
    processTreeQueue: DispatchQueue = DispatchQueue(label: "test.process-tree")
) -> FilterInteractor {
    let ref = WeakBox<FilterInteractor>()
    let pipeline = FileAuthPipeline(
        processTree: processTree,
        rulesProvider: { ref.value?.currentRules() ?? [] },
        allowlistProvider: { ref.value?.currentAllowlist() ?? [] },
        ancestorAllowlistProvider: { ref.value?.currentAncestorAllowlist() ?? [] },
        postRespond: { _, _, _, _ in }
    )
    let interactor = FilterInteractor(
        initialRules: rules,
        initialAllowlist: allowlist,
        initialAncestorAllowlist: ancestorAllowlist,
        initialJailRules: jailRules,
        processTree: processTree,
        pipeline: pipeline,
        processTreeQueue: processTreeQueue
    )
    ref.value = interactor
    pipeline.start()
    return interactor
}

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
    ) -> FileAuthEvent {
        FileAuthEvent(
            correlationID: UUID(),
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
            respond: { allowed, _ in respond(allowed) }
        )
    }

    private func openFileEventCapturingCache(
        path: String,
        processPath: String = "/usr/bin/test",
        teamID: String = "",
        signingID: String = "",
        processIdentity: ProcessIdentity? = nil,
        deadline: UInt64 = 0,
        respond: @escaping @Sendable (Bool, Bool) -> Void
    ) -> FileAuthEvent {
        FileAuthEvent(
            correlationID: UUID(),
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
        let queue = DispatchQueue(label: "test.process-tree")
        let interactor = makeInteractor(processTree: tree, processTreeQueue: queue)
        let child = record(pid: 200, parentPID: 100, path: "/usr/bin/child")

        interactor.handleFork(child: child)
        queue.sync {}

        #expect(tree.insertedIdentities == [child.identity])
    }

    @Test("exec event inserts new image into process tree")
    func execInsertsNewImage() {
        let tree = FakeProcessTree()
        let queue = DispatchQueue(label: "test.process-tree")
        let interactor = makeInteractor(processTree: tree, processTreeQueue: queue)
        let newImage = record(pid: 200, parentPID: 100, path: "/usr/bin/shell")

        interactor.handleExec(newImage: newImage)
        queue.sync {}

        #expect(tree.insertedIdentities == [newImage.identity])
    }

    @Test("exit event removes identity from process tree")
    func exitRemovesIdentity() {
        let tree = FakeProcessTree()
        let queue = DispatchQueue(label: "test.process-tree")
        let interactor = makeInteractor(processTree: tree, processTreeQueue: queue)
        let processIdentity = identity(pid: 200)

        interactor.handleExit(identity: processIdentity)
        queue.sync {}

        #expect(tree.removedIdentities == [processIdentity])
    }

    @Test("openFile with no matching rule allows access without consulting tree")
    func openFileNoRuleAllows() async {
        let tree = FakeProcessTree()
        let interactor = makeInteractor(processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(path: "/tmp/file.txt") { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
        #expect(tree.insertedIdentities.isEmpty)
        #expect(tree.removedIdentities.isEmpty)
    }

    @Test("openFile allowed by process signature without consulting tree for ancestry")
    func openFileAllowedBySignature() async {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let tree = FakeProcessTree()
        let interactor = makeInteractor(rules: [rule], processTree: tree)

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

    @Test("openFile denied when process signature does not match")
    func openFileDeniedBySignatureMismatch() async {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedSignatures: [ProcessSignature(teamID: "TEAM1", signingID: "com.example.app")]
        )
        let tree = FakeProcessTree()
        let interactor = makeInteractor(rules: [rule], processTree: tree)

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
        let interactor = makeInteractor(rules: [rule], processTree: tree)

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
        let interactor = makeInteractor(rules: [rule], processTree: tree)

        // deadline = 0 ensures waitForProcess exits immediately without spinning
        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(path: "/protected/file.txt", deadline: 0) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == false)
    }

    @Test("openFile denied when ancestor path does not match allowed ancestor")
    func openFileDeniedWhenAncestorPathMismatches() async {
        let rule = FAARule(
            protectedPathPrefix: "/protected",
            source: .user,
            allowedAncestorProcessPaths: ["/usr/bin/terminal"]
        )
        let tree = FakeProcessTree()
        tree.containsResult = true
        tree.ancestorsResult = [AncestorInfo(path: "/usr/bin/other", teamID: "", signingID: "")]
        let interactor = makeInteractor(rules: [rule], processTree: tree)

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
        let interactor = makeInteractor(rules: [rule], allowlist: [allowlistEntry], processTree: tree)

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
        let interactor = makeInteractor(allowlist: [allowlistEntry], processTree: tree)

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
        let interactor = makeInteractor(rules: [rule], ancestorAllowlist: [ancestorEntry], processTree: tree)

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

    @Test("process denied when ancestor does not match ancestor allowlist entry")
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
        let interactor = makeInteractor(rules: [rule], ancestorAllowlist: [ancestorEntry], processTree: tree)

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

    @Test("openFile allowed by process path without consulting tree when rule also has ancestor criteria")
    func openFileProcessPathMatchSkipsAncestryLookup() async {
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
        let interactor = makeInteractor(rules: [rule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/protected/file.txt",
                processPath: "/usr/bin/safe",
                deadline: 0  // immediate deadline — any wait would expire instantly
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }

    // MARK: - Jail tests

    @Test("jailed process allowed when accessing path within allowed prefixes")
    func jailedProcessAllowedWithinPrefixes() async {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed/**"]
        )
        let tree = FakeProcessTree()
        let interactor = makeInteractor(jailRules: [jailRule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/allowed/data.db",
                teamID: "TEAM1",
                signingID: "com.example.jailed"
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }

    @Test("globally allowlisted process escapes jail")
    func globallyAllowlistedProcessEscapesJail() async {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed"]
        )
        let allowlistEntry = AllowlistEntry(signingID: "com.example.jailed", teamID: "TEAM1")
        let tree = FakeProcessTree()
        let interactor = makeInteractor(allowlist: [allowlistEntry], jailRules: [jailRule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/forbidden/file.txt",
                teamID: "TEAM1",
                signingID: "com.example.jailed"
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }

    @Test("non-jailed process is unaffected by jail rules")
    func nonJailedProcessUnaffected() async {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed"]
        )
        let tree = FakeProcessTree()
        let interactor = makeInteractor(jailRules: [jailRule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/forbidden/file.txt",
                teamID: "OTHER",
                signingID: "com.other.app"
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }

    // MARK: - handleJailEventSync (inherited jail path)

    @Test("handleJailEventSync allows path within rule's allowed prefixes for inherited process")
    func inheritedJailAllowsPathWithinPrefixes() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed/**"]
        )
        let interactor = makeInteractor(jailRules: [jailRule], processTree: FakeProcessTree())
        var allowed: Bool?

        let event = openFileEvent(path: "/allowed/data.db", teamID: "OTHER", signingID: "com.child.process") { allowed = $0 }
        interactor.handleJailEventSync(event, jailRuleID: jailRule.id)

        #expect(allowed == true)
    }

    @Test("handleJailEventSync denies path outside rule's allowed prefixes for inherited process")
    func inheritedJailDeniesPathOutsidePrefixes() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed/**"]
        )
        let interactor = makeInteractor(jailRules: [jailRule], processTree: FakeProcessTree())
        var allowed: Bool?

        let event = openFileEvent(path: "/forbidden/file", teamID: "OTHER", signingID: "com.child.process") { allowed = $0 }
        interactor.handleJailEventSync(event, jailRuleID: jailRule.id)

        #expect(allowed == false)
    }

    @Test("handleJailEventSync allows when rule ID no longer exists (stale mute)")
    func inheritedJailStaleRuleAllows() {
        let interactor = makeInteractor(processTree: FakeProcessTree())
        var allowed: Bool?

        let event = openFileEvent(path: "/any/path", teamID: "OTHER", signingID: "com.child.process") { allowed = $0 }
        interactor.handleJailEventSync(event, jailRuleID: UUID())

        #expect(allowed == true)
    }

    @Test("handleJailEventSync: globally allowlisted process escapes inherited jail")
    func inheritedJailAllowlistEscape() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: []
        )
        let allowlistEntry = AllowlistEntry(signingID: "com.child.process", teamID: "OTHER")
        let interactor = makeInteractor(allowlist: [allowlistEntry], jailRules: [jailRule], processTree: FakeProcessTree())
        var allowed: Bool?

        let event = openFileEvent(path: "/forbidden/file", teamID: "OTHER", signingID: "com.child.process") { allowed = $0 }
        interactor.handleJailEventSync(event, jailRuleID: jailRule.id)

        #expect(allowed == true)
    }

    @Test("handleJailEventSync: globally allowlisted process responds with cache enabled")
    func jailEventGloballyAllowlistedProcessCaches() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: []
        )
        let allowlistEntry = AllowlistEntry(signingID: "com.child.process", teamID: "OTHER")
        let interactor = makeInteractor(allowlist: [allowlistEntry], jailRules: [jailRule], processTree: FakeProcessTree())
        var cached: Bool?

        let event = openFileEventCapturingCache(path: "/forbidden/file", teamID: "OTHER", signingID: "com.child.process") { _, cache in cached = cache }
        interactor.handleJailEventSync(event, jailRuleID: jailRule.id)

        #expect(cached == true)
    }

    // MARK: - Ancestor jail propagation via handleFileAuth

    @Test("descendant of jailed ancestor is allowed access within allowed prefixes")
    func ancestorJailAllowsDescendantWithinPrefixes() async {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed/**"]
        )
        let tree = FakeProcessTree()
        tree.containsResult = true
        tree.ancestorsResult = [AncestorInfo(path: "/usr/bin/app", teamID: "TEAM1", signingID: "com.example.jailed")]
        let interactor = makeInteractor(jailRules: [jailRule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/allowed/data.db",
                teamID: "OTHER",
                signingID: "com.child.process"
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }

    @Test("globally allowlisted descendant escapes ancestor jail")
    func globalAllowlistEscapesAncestorJail() async {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: []
        )
        let allowlistEntry = AllowlistEntry(signingID: "com.child.process", teamID: "OTHER")
        let tree = FakeProcessTree()
        tree.containsResult = true
        tree.ancestorsResult = [AncestorInfo(path: "/usr/bin/app", teamID: "TEAM1", signingID: "com.example.jailed")]
        let interactor = makeInteractor(allowlist: [allowlistEntry], jailRules: [jailRule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/forbidden/file",
                teamID: "OTHER",
                signingID: "com.child.process"
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }

    @Test("no ancestor jail match leaves process unaffected")
    func noAncestorJailMatchUnaffected() async {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed"]
        )
        let tree = FakeProcessTree()
        tree.containsResult = true
        tree.ancestorsResult = [AncestorInfo(path: "/usr/bin/other", teamID: "OTHER", signingID: "com.other.app")]
        let interactor = makeInteractor(jailRules: [jailRule], processTree: tree)

        let allowed: Bool = await withCheckedContinuation { continuation in
            interactor.handleFileAuth(openFileEvent(
                path: "/forbidden/file.txt",
                teamID: "OTHER",
                signingID: "com.other.app"
            ) { result in
                continuation.resume(returning: result)
            })
        }

        #expect(allowed == true)
    }
}
