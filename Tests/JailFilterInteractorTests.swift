//
//  JailFilterInteractorTests.swift
//  clearancekitTests
//

import Testing
import Foundation

// MARK: - JailFilterInteractorTests

private final class FakeProcessTree: @unchecked Sendable, ProcessTreeProtocol {
    var ancestorsResult: [AncestorInfo] = []

    func insert(_ record: ProcessRecord) {}
    func remove(identity: ProcessIdentity) {}
    func contains(identity: ProcessIdentity) -> Bool { false }
    func ancestors(of identity: ProcessIdentity) -> [AncestorInfo] { ancestorsResult }
    func allRecords() -> [ProcessRecord] { [] }
}

private func makeJailInteractor(
    jailRules: [JailRule] = [],
    allowlist: [AllowlistEntry] = [],
    processTree: ProcessTreeProtocol = FakeProcessTree()
) -> JailFilterInteractor {
    let allowlistState = AllowlistState(initialAllowlist: allowlist)
    let postRespondHandler = PostRespondHandler()
    return JailFilterInteractor(
        initialJailRules: jailRules,
        allowlistState: allowlistState,
        processTree: processTree,
        postRespondHandler: postRespondHandler
    )
}

private func identity(pid: pid_t, version: UInt32 = 1) -> ProcessIdentity {
    ProcessIdentity(pid: pid, pidVersion: version)
}

private func openFileEvent(
    path: String,
    processPath: String = "/usr/bin/test",
    teamID: String = "",
    signingID: String = "",
    respond: @escaping @Sendable (Bool) -> Void
) -> FileAuthEvent {
    FileAuthEvent(
        correlationID: UUID(),
        operation: .open,
        path: path,
        processIdentity: identity(pid: 100),
        processID: 100,
        parentPID: 1,
        processPath: processPath,
        teamID: teamID,
        signingID: signingID,
        uid: 501,
        gid: 20,
        ttyPath: nil,
        deadline: 0,
        respond: { allowed, _ in respond(allowed) }
    )
}

private func openFileEventCapturingCache(
    path: String,
    teamID: String = "",
    signingID: String = "",
    respond: @escaping @Sendable (Bool, Bool) -> Void
) -> FileAuthEvent {
    FileAuthEvent(
        correlationID: UUID(),
        operation: .open,
        path: path,
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

@Suite("JailFilterInteractor — handleJailEventSync")
struct JailFilterInteractorTests {

    @Test("allows path within rule's allowed prefixes for inherited process")
    func allowsPathWithinPrefixes() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed/**"]
        )
        let interactor = makeJailInteractor(jailRules: [jailRule])
        var allowed: Bool?

        let event = openFileEvent(path: "/allowed/data.db", teamID: "OTHER", signingID: "com.child.process") { allowed = $0 }
        interactor.handleJailEventSync(event, jailRuleID: jailRule.id)

        #expect(allowed == true)
    }

    @Test("denies path outside rule's allowed prefixes for inherited process")
    func deniesPathOutsidePrefixes() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed/**"]
        )
        let interactor = makeJailInteractor(jailRules: [jailRule])
        var allowed: Bool?

        let event = openFileEvent(path: "/forbidden/file", teamID: "OTHER", signingID: "com.child.process") { allowed = $0 }
        interactor.handleJailEventSync(event, jailRuleID: jailRule.id)

        #expect(allowed == false)
    }

    @Test("allows when rule ID no longer exists (stale mute)")
    func staleRuleAllows() {
        let interactor = makeJailInteractor()
        var allowed: Bool?

        let event = openFileEvent(path: "/any/path", teamID: "OTHER", signingID: "com.child.process") { allowed = $0 }
        interactor.handleJailEventSync(event, jailRuleID: UUID())

        #expect(allowed == true)
    }

    @Test("globally allowlisted process escapes inherited jail")
    func allowlistEscape() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: []
        )
        let allowlistEntry = AllowlistEntry(signingID: "com.child.process", teamID: "OTHER")
        let interactor = makeJailInteractor(jailRules: [jailRule], allowlist: [allowlistEntry])
        var allowed: Bool?

        let event = openFileEvent(path: "/forbidden/file", teamID: "OTHER", signingID: "com.child.process") { allowed = $0 }
        interactor.handleJailEventSync(event, jailRuleID: jailRule.id)

        #expect(allowed == true)
    }

    @Test("globally allowlisted process responds with cache enabled")
    func allowlistedProcessCaches() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: []
        )
        let allowlistEntry = AllowlistEntry(signingID: "com.child.process", teamID: "OTHER")
        let interactor = makeJailInteractor(jailRules: [jailRule], allowlist: [allowlistEntry])
        var cached: Bool?

        let event = openFileEventCapturingCache(path: "/forbidden/file", teamID: "OTHER", signingID: "com.child.process") { _, cache in cached = cache }
        interactor.handleJailEventSync(event, jailRuleID: jailRule.id)

        #expect(cached == true)
    }

    @Test("updateJailRules takes effect on next event")
    func updateJailRules() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed/**"]
        )
        let interactor = makeJailInteractor()
        interactor.updateJailRules([jailRule])
        var allowed: Bool?

        let event = openFileEvent(path: "/forbidden/file", teamID: "OTHER", signingID: "com.child.process") { allowed = $0 }
        interactor.handleJailEventSync(event, jailRuleID: jailRule.id)

        #expect(allowed == false)
    }

    @Test("jailMetrics increments evaluated and deny counts correctly")
    func jailMetrics() {
        let jailRule = JailRule(
            name: "Confine App",
            jailedSignature: ProcessSignature(teamID: "TEAM1", signingID: "com.example.jailed"),
            allowedPathPrefixes: ["/allowed/**"]
        )
        let interactor = makeJailInteractor(jailRules: [jailRule])

        let allowedEvent = openFileEvent(path: "/allowed/ok") { _ in }
        let deniedEvent = openFileEvent(path: "/forbidden/no") { _ in }

        interactor.handleJailEventSync(allowedEvent, jailRuleID: jailRule.id)
        interactor.handleJailEventSync(deniedEvent, jailRuleID: jailRule.id)

        let metrics = interactor.jailMetrics()
        #expect(metrics.jailEvaluatedCount == 2)
        #expect(metrics.jailDenyCount == 1)
    }
}
