# Per-rule Touch ID Authorization for File Access

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `FAARule` so a rule can require Touch ID authorization before allowing a matching process to access a protected path, with a sliding-window session so repeat accesses from the same process do not re-prompt. This resolves GitHub issue #141.

**Architecture:** Three-layer hexagonal as per `CLAUDE.md`. Domain changes (`Shared/FAAPolicy.swift`, `Shared/XPCProtocol.swift`) define the new decision case and cross-process protocol. A new adapter `opfilter/XPC/AuthorizationGate.swift` owns the session store and the XPC dispatch to the GUI. The GUI app grows `clearancekit/Authorization/AuthorizationRequestWindow.swift` which drives `LAContext` and a countdown panel, and `clearancekit/App/XPCClient.swift` relays the opfilter callback to that window. `RuleEditView` gains UI for the three new fields.

**Tech Stack:** Swift, Swift Testing framework (`@Suite`, `@Test`, `#expect`), Endpoint Security, NSXPC, LocalAuthentication (`LAContext`), SwiftUI/AppKit.

**Build command:** `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
**Expected after every test step:** `** TEST SUCCEEDED **`

---

## Task 1: FAARule — three new fields with signature-compatible Codable

**Files:**
- `Shared/FAAPolicy.swift` (edit)
- `Tests/FAARule+AuthorizationEncodingTests.swift` (new)

- [ ] **Step 1.1: Write characterisation tests first (RED)**

Create `Tests/FAARule+AuthorizationEncodingTests.swift` with:

```swift
//
//  FAARule+AuthorizationEncodingTests.swift
//  clearancekitTests
//

import Foundation
import Testing
@testable import clearancekit

@Suite("FAARule authorization fields")
struct FAARuleAuthorizationEncodingTests {
    @Test("round-trips authorizedSignatures, requiresAuthorization and sessionDuration")
    func roundTripsAllAuthorizationFields() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/me/Secrets",
            authorizedSignatures: [ProcessSignature(teamID: "ABCDE12345", signingID: "com.example.app")],
            requiresAuthorization: true,
            authorizationSessionDuration: 600
        )
        let encoded = try JSONEncoder().encode(rule)
        let decoded = try JSONDecoder().decode(FAARule.self, from: encoded)
        #expect(decoded.authorizedSignatures == rule.authorizedSignatures)
        #expect(decoded.requiresAuthorization == true)
        #expect(decoded.authorizationSessionDuration == 600)
    }

    @Test("omits authorization keys from JSON when defaults")
    func omitsDefaultsFromJSON() throws {
        let rule = FAARule(protectedPathPrefix: "/Users/me/Secrets")
        let encoded = try JSONEncoder().encode(rule)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        #expect(!json.contains("authorizedSignatures"))
        #expect(!json.contains("requiresAuthorization"))
        #expect(!json.contains("authorizationSessionDuration"))
    }

    @Test("omits sessionDuration from canonical JSON when equal to 300 default")
    func omitsDefaultSessionDurationFromCanonicalJSON() throws {
        let rule = FAARule(
            protectedPathPrefix: "/Users/me/Secrets",
            requiresAuthorization: true,
            authorizationSessionDuration: 300
        )
        let encoded = try JSONEncoder().encode(rule)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        #expect(json.contains("requiresAuthorization"))
        #expect(!json.contains("authorizationSessionDuration"))
    }

    @Test("decodes rule written by older build with no authorization keys")
    func decodesLegacyRule() throws {
        let legacy = """
        {"id":"\(UUID().uuidString)","protectedPathPrefix":"/tmp","source":"user","allowedProcessPaths":[],"allowedSignatures":[],"allowedAncestorProcessPaths":[],"allowedAncestorSignatures":[]}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(FAARule.self, from: legacy)
        #expect(decoded.authorizedSignatures.isEmpty)
        #expect(decoded.requiresAuthorization == false)
        #expect(decoded.authorizationSessionDuration == 300)
    }
}
```

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: build fails — the new fields do not exist yet.

- [ ] **Step 1.2: Add fields and encoder/decoder (GREEN)**

Edit `Shared/FAAPolicy.swift`. In the `FAARule` struct, add the three stored properties after `requireValidSigning`:

```swift
    /// Signatures that may access this path but only after Touch ID authorization.
    /// A successful prompt opens a sliding-window session keyed by (pid, pidVersion, prefix).
    public var authorizedSignatures: [ProcessSignature]

    /// When true, every process with a non-empty team ID must pass Touch ID
    /// before access is allowed. Unsigned processes (empty team ID) are still
    /// denied outright — the prompt is not a route around missing signing.
    public let requiresAuthorization: Bool

    /// Seconds of inactivity after which an authorized session expires. Each
    /// in-session access resets the timer.
    public let authorizationSessionDuration: TimeInterval
```

Replace the initializer with one that accepts the new fields (defaults preserve the public API):

```swift
    public init(
        id: UUID = UUID(),
        protectedPathPrefix: String,
        source: RuleSource = .user,
        allowedProcessPaths: [String] = [],
        allowedSignatures: [ProcessSignature] = [],
        allowedAncestorProcessPaths: [String] = [],
        allowedAncestorSignatures: [ProcessSignature] = [],
        enforceOnWriteOnly: Bool = false,
        requireValidSigning: Bool = false,
        authorizedSignatures: [ProcessSignature] = [],
        requiresAuthorization: Bool = false,
        authorizationSessionDuration: TimeInterval = 300
    ) {
        self.id = id
        self.protectedPathPrefix = protectedPathPrefix
        self.source = source
        self.allowedProcessPaths = allowedProcessPaths
        self.allowedSignatures = allowedSignatures
        self.allowedAncestorProcessPaths = allowedAncestorProcessPaths
        self.allowedAncestorSignatures = allowedAncestorSignatures
        self.enforceOnWriteOnly = enforceOnWriteOnly
        self.requireValidSigning = requireValidSigning
        self.authorizedSignatures = authorizedSignatures
        self.requiresAuthorization = requiresAuthorization
        self.authorizationSessionDuration = authorizationSessionDuration
    }
```

Extend `CodingKeys` with the three new keys:

```swift
    private enum CodingKeys: String, CodingKey {
        case id, protectedPathPrefix, source, allowedProcessPaths, allowedSignatures,
             allowedAncestorProcessPaths, allowedAncestorSignatures,
             enforceOnWriteOnly, requireValidSigning,
             authorizedSignatures, requiresAuthorization, authorizationSessionDuration
    }
```

Extend `init(from:)`:

```swift
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        protectedPathPrefix = try c.decode(String.self, forKey: .protectedPathPrefix)
        source = (try? c.decode(RuleSource.self, forKey: .source)) ?? .user
        allowedProcessPaths = (try? c.decode([String].self, forKey: .allowedProcessPaths)) ?? []
        allowedSignatures = (try? c.decode([ProcessSignature].self, forKey: .allowedSignatures)) ?? []
        allowedAncestorProcessPaths = (try? c.decode([String].self, forKey: .allowedAncestorProcessPaths)) ?? []
        allowedAncestorSignatures = (try? c.decode([ProcessSignature].self, forKey: .allowedAncestorSignatures)) ?? []
        enforceOnWriteOnly = (try? c.decode(Bool.self, forKey: .enforceOnWriteOnly)) ?? false
        requireValidSigning = (try? c.decode(Bool.self, forKey: .requireValidSigning)) ?? false
        authorizedSignatures = (try? c.decode([ProcessSignature].self, forKey: .authorizedSignatures)) ?? []
        requiresAuthorization = (try? c.decode(Bool.self, forKey: .requiresAuthorization)) ?? false
        authorizationSessionDuration = (try? c.decode(TimeInterval.self, forKey: .authorizationSessionDuration)) ?? 300
    }
```

Extend `encode(to:)` to omit the three keys when they hold default values (same pattern used for `enforceOnWriteOnly`):

```swift
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(protectedPathPrefix, forKey: .protectedPathPrefix)
        try c.encode(source, forKey: .source)
        try c.encode(allowedProcessPaths, forKey: .allowedProcessPaths)
        try c.encode(allowedSignatures, forKey: .allowedSignatures)
        try c.encode(allowedAncestorProcessPaths, forKey: .allowedAncestorProcessPaths)
        try c.encode(allowedAncestorSignatures, forKey: .allowedAncestorSignatures)
        if enforceOnWriteOnly {
            try c.encode(enforceOnWriteOnly, forKey: .enforceOnWriteOnly)
        }
        if requireValidSigning {
            try c.encode(requireValidSigning, forKey: .requireValidSigning)
        }
        if !authorizedSignatures.isEmpty {
            try c.encode(authorizedSignatures, forKey: .authorizedSignatures)
        }
        if requiresAuthorization {
            try c.encode(requiresAuthorization, forKey: .requiresAuthorization)
        }
        if authorizationSessionDuration != 300 {
            try c.encode(authorizationSessionDuration, forKey: .authorizationSessionDuration)
        }
    }
```

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: `** TEST SUCCEEDED **`.

- [ ] **Step 1.3: Commit**

```bash
git add Shared/FAAPolicy.swift Tests/FAARule+AuthorizationEncodingTests.swift
git commit -m "$(cat <<'EOF'
Add authorization fields to FAARule with signature-compatible encoding

Introduces authorizedSignatures, requiresAuthorization, and
authorizationSessionDuration. The custom encoder omits each field when it
holds its default value so canonical JSON for pre-existing rules remains
byte-identical and their stored signatures continue to verify.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: PolicyDecision — `.requiresAuthorization` and the evaluation branch

**Files:**
- `Shared/FAAPolicy.swift` (edit)
- `Tests/PolicyDecision+AuthorizationTests.swift` (new)

- [ ] **Step 2.1: Characterisation + new-behaviour tests (RED)**

Create `Tests/PolicyDecision+AuthorizationTests.swift`:

```swift
//
//  PolicyDecision+AuthorizationTests.swift
//  clearancekitTests
//

import Foundation
import Testing
@testable import clearancekit

@Suite("Authorization decisions")
struct PolicyDecisionAuthorizationTests {
    @Test("authorizedSignatures match returns requiresAuthorization")
    func authorizedSignatureRequestsPrompt() {
        let rule = FAARule(
            protectedPathPrefix: "/Secrets",
            authorizedSignatures: [ProcessSignature(teamID: "ABCDE12345", signingID: "com.example.app")],
            authorizationSessionDuration: 600
        )
        let decision = checkFAAPolicy(
            rules: [rule], path: "/Secrets/file.txt", processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            accessKind: .write, ancestors: []
        )
        guard case .requiresAuthorization(_, _, _, let criterion, let duration) = decision else {
            Issue.record("expected requiresAuthorization, got \(decision)"); return
        }
        #expect(criterion == "authorizedSignature")
        #expect(duration == 600)
        #expect(decision.isAllowed == false)
    }

    @Test("requiresAuthorization with a valid team ID returns requiresAuthorization")
    func catchAllRequiresAuthorization() {
        let rule = FAARule(
            protectedPathPrefix: "/Secrets",
            requiresAuthorization: true
        )
        let decision = checkFAAPolicy(
            rules: [rule], path: "/Secrets/file.txt", processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            accessKind: .write, ancestors: []
        )
        guard case .requiresAuthorization(_, _, _, let criterion, _) = decision else {
            Issue.record("expected requiresAuthorization, got \(decision)"); return
        }
        #expect(criterion == "requiresAuthorization")
    }

    @Test("requiresAuthorization with empty team ID falls through to denied")
    func unsignedBypassesPromptAndIsDenied() {
        let rule = FAARule(
            protectedPathPrefix: "/Secrets",
            requiresAuthorization: true
        )
        let decision = checkFAAPolicy(
            rules: [rule], path: "/Secrets/file.txt", processPath: "/Apps/Example",
            teamID: "", signingID: "",
            accessKind: .write, ancestors: []
        )
        if case .requiresAuthorization = decision {
            Issue.record("unsigned process must not get a Touch ID prompt")
        }
        #expect(decision.isAllowed == false)
    }

    @Test("allowedSignatures takes priority over authorizedSignatures")
    func allowedBeatsAuthorized() {
        let signature = ProcessSignature(teamID: "ABCDE12345", signingID: "com.example.app")
        let rule = FAARule(
            protectedPathPrefix: "/Secrets",
            allowedSignatures: [signature],
            authorizedSignatures: [signature],
            requiresAuthorization: true
        )
        let decision = checkFAAPolicy(
            rules: [rule], path: "/Secrets/file.txt", processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            accessKind: .write, ancestors: []
        )
        guard case .allowed = decision else {
            Issue.record("expected .allowed, got \(decision)"); return
        }
    }

    @Test("enforceOnWriteOnly skips the rule for reads even when authorization is set")
    func writeOnlyRuleSkippedOnRead() {
        let rule = FAARule(
            protectedPathPrefix: "/Secrets",
            enforceOnWriteOnly: true,
            requiresAuthorization: true
        )
        let decision = checkFAAPolicy(
            rules: [rule], path: "/Secrets/file.txt", processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            accessKind: .read, ancestors: []
        )
        guard case .noRuleApplies = decision else {
            Issue.record("expected .noRuleApplies, got \(decision)"); return
        }
    }
}
```

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: build fails — `.requiresAuthorization` case does not exist.

- [ ] **Step 2.2: Add the case, fix `isAllowed`, wire the branch (GREEN)**

In `Shared/FAAPolicy.swift`, add the case to `PolicyDecision` after `.jailDenied`:

```swift
    /// Covered by a rule that allows access only after Touch ID authorization.
    /// The filter must drive the GUI prompt and either open a session or deny.
    case requiresAuthorization(
        ruleID: UUID,
        ruleName: String,
        ruleSource: RuleSource,
        criterion: String,
        sessionDuration: TimeInterval
    )
```

Update `isAllowed` to include the new case in the deny set:

```swift
    public var isAllowed: Bool {
        switch self {
        case .denied, .jailDenied, .requiresAuthorization: return false
        default: return true
        }
    }
```

Add a matching branch to `matchedRuleID`:

```swift
    public var matchedRuleID: UUID? {
        switch self {
        case .allowed(let ruleID, _, _, _): return ruleID
        case .denied(let ruleID, _, _, _): return ruleID
        case .jailAllowed(let ruleID, _, _): return ruleID
        case .jailDenied(let ruleID, _, _): return ruleID
        case .requiresAuthorization(let ruleID, _, _, _, _): return ruleID
        default: return nil
        }
    }
```

Add a branch to `policyName`, `policySource`, and `reason`:

```swift
    public var policyName: String {
        switch self {
        case .allowed(_, let name, _, _): return name
        case .denied(_, let name, _, _): return name
        case .jailAllowed(_, let name, _): return name
        case .jailDenied(_, let name, _): return name
        case .requiresAuthorization(_, let name, _, _, _): return name
        default: return ""
        }
    }

    public var policySource: RuleSource? {
        switch self {
        case .allowed(_, _, let source, _): return source
        case .denied(_, _, let source, _): return source
        case .requiresAuthorization(_, _, let source, _, _): return source
        default: return nil
        }
    }

    public var reason: String {
        switch self {
        case .globallyAllowed:
            return "Globally allowed"
        case .noRuleApplies:
            return "No rule applies — default allow"
        case .allowed(_, _, _, let criterion):
            return "Allowed: matched \(criterion)"
        case .denied(_, let ruleName, _, let criteria):
            return "Denied by rule \"\(ruleName)\" — allowed: \(criteria)"
        case .jailAllowed(_, let ruleName, let prefix):
            return "Jail \"\(ruleName)\" — allowed: matched prefix \(prefix)"
        case .jailDenied(_, let ruleName, let prefixes):
            return "Denied by jail \"\(ruleName)\" — allowed prefixes: \(prefixes.joined(separator: ", "))"
        case .requiresAuthorization(_, let ruleName, _, let criterion, _):
            return "Requires Touch ID for rule \"\(ruleName)\" — matched \(criterion)"
        }
    }
```

In `checkFAAPolicy`, after the `allowedSignatures` block and before the `allowedAncestorProcessPaths` block, insert:

```swift
        if !rule.authorizedSignatures.isEmpty,
           rule.authorizedSignatures.contains(where: { $0.matches(resolvedTeamID: teamID, signingID: signingID) }) {
            return .requiresAuthorization(
                ruleID: rule.id,
                ruleName: rule.protectedPathPrefix,
                ruleSource: rule.source,
                criterion: "authorizedSignature",
                sessionDuration: rule.authorizationSessionDuration
            )
        }

        if rule.requiresAuthorization && !teamID.isEmpty {
            return .requiresAuthorization(
                ruleID: rule.id,
                ruleName: rule.protectedPathPrefix,
                ruleSource: rule.source,
                criterion: "requiresAuthorization",
                sessionDuration: rule.authorizationSessionDuration
            )
        }
```

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: `** TEST SUCCEEDED **`.

- [ ] **Step 2.3: Commit**

```bash
git add Shared/FAAPolicy.swift Tests/PolicyDecision+AuthorizationTests.swift
git commit -m "$(cat <<'EOF'
Add PolicyDecision.requiresAuthorization and policy evaluation branch

Introduces a new PolicyDecision case that indicates Touch ID authorization
is required and threads it through isAllowed, policyName, policySource,
matchedRuleID, and reason. checkFAAPolicy now short-circuits to the new
case when either authorizedSignatures matches or requiresAuthorization is
set on a rule with a non-empty team ID.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: AuthorizationGate — in-memory session store

**Files:**
- `opfilter/XPC/AuthorizationGate.swift` (new)
- `Tests/AuthorizationGateTests.swift` (new)

- [ ] **Step 3.1: Write session-store tests first (RED)**

Create `Tests/AuthorizationGateTests.swift`:

```swift
//
//  AuthorizationGateTests.swift
//  clearancekitTests
//

import Foundation
import Testing
@testable import opfilter

@Suite("AuthorizationGate session store")
struct AuthorizationGateTests {
    @Test("no session — hasActiveSession is false")
    func emptyStoreReportsNoSession() {
        let gate = AuthorizationGate()
        #expect(gate.hasActiveSession(pid: 1234, pidVersion: 7, prefix: "/Secrets") == false)
    }

    @Test("after createSession — active")
    func createdSessionIsActive() {
        let gate = AuthorizationGate()
        gate.createSession(pid: 1234, pidVersion: 7, prefix: "/Secrets", duration: 60)
        #expect(gate.hasActiveSession(pid: 1234, pidVersion: 7, prefix: "/Secrets") == true)
    }

    @Test("touchSession keeps session alive")
    func touchedSessionStaysActive() {
        let gate = AuthorizationGate()
        gate.createSession(pid: 1234, pidVersion: 7, prefix: "/Secrets", duration: 60)
        gate.touchSession(pid: 1234, pidVersion: 7, prefix: "/Secrets")
        #expect(gate.hasActiveSession(pid: 1234, pidVersion: 7, prefix: "/Secrets") == true)
    }

    @Test("session expires after its duration")
    func expiredSessionIsInactive() {
        let gate = AuthorizationGate()
        gate.createSession(pid: 1234, pidVersion: 7, prefix: "/Secrets", duration: 0.01)
        Thread.sleep(forTimeInterval: 0.02)
        #expect(gate.hasActiveSession(pid: 1234, pidVersion: 7, prefix: "/Secrets") == false)
    }

    @Test("sessions are keyed by pid, pidVersion, and prefix")
    func distinctKeysAreIndependent() {
        let gate = AuthorizationGate()
        gate.createSession(pid: 1234, pidVersion: 7, prefix: "/Secrets", duration: 60)
        #expect(gate.hasActiveSession(pid: 1234, pidVersion: 8, prefix: "/Secrets") == false)
        #expect(gate.hasActiveSession(pid: 9999, pidVersion: 7, prefix: "/Secrets") == false)
        #expect(gate.hasActiveSession(pid: 1234, pidVersion: 7, prefix: "/Other") == false)
    }
}
```

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: build fails — `AuthorizationGate` does not exist.

- [ ] **Step 3.2: Create the session store (GREEN)**

Create `opfilter/XPC/AuthorizationGate.swift`:

```swift
//
//  AuthorizationGate.swift
//  opfilter
//
//  Session-keyed authorization cache. A successful Touch ID prompt opens
//  a sliding-window session keyed by (pid, pidVersion, protectedPathPrefix).
//  Subsequent accesses within the window are allowed without re-prompting
//  and each access pushes the expiry forward.
//

import Foundation
import os

struct AuthSessionKey: Hashable {
    let pid: pid_t
    let pidVersion: UInt32
    let pathPrefix: String
}

struct AuthSession {
    var lastAccess: Date
    let duration: TimeInterval

    var isActive: Bool {
        Date().timeIntervalSince(lastAccess) < duration
    }
}

final class AuthorizationGate: @unchecked Sendable {
    private let sessions: OSAllocatedUnfairLock<[AuthSessionKey: AuthSession]>

    init() {
        self.sessions = OSAllocatedUnfairLock(initialState: [:])
    }

    func hasActiveSession(pid: pid_t, pidVersion: UInt32, prefix: String) -> Bool {
        let key = AuthSessionKey(pid: pid, pidVersion: pidVersion, pathPrefix: prefix)
        return sessions.withLock { store in
            guard let session = store[key] else { return false }
            if session.isActive { return true }
            store.removeValue(forKey: key)
            return false
        }
    }

    func touchSession(pid: pid_t, pidVersion: UInt32, prefix: String) {
        let key = AuthSessionKey(pid: pid, pidVersion: pidVersion, pathPrefix: prefix)
        sessions.withLock { store in
            guard var session = store[key] else { return }
            session.lastAccess = Date()
            store[key] = session
        }
    }

    func createSession(pid: pid_t, pidVersion: UInt32, prefix: String, duration: TimeInterval) {
        let key = AuthSessionKey(pid: pid, pidVersion: pidVersion, pathPrefix: prefix)
        sessions.withLock { store in
            store[key] = AuthSession(lastAccess: Date(), duration: duration)
        }
    }
}
```

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: `** TEST SUCCEEDED **`.

- [ ] **Step 3.3: Commit**

```bash
git add opfilter/XPC/AuthorizationGate.swift Tests/AuthorizationGateTests.swift
git commit -m "$(cat <<'EOF'
Add AuthorizationGate session store

In-memory, lock-guarded session cache keyed by (pid, pidVersion, prefix)
with a sliding inactivity window. Provides the lookup/create/touch
primitives that the pipeline will use to avoid re-prompting Touch ID
for rapid successive accesses from the same process.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: XPC protocol — `requestAuthorization` with reply block

**Files:**
- `Shared/XPCProtocol.swift` (edit)
- `clearancekit/App/XPCClient.swift` (edit — stub conformance)

- [ ] **Step 4.1: Extend the client protocol**

In `Shared/XPCProtocol.swift`, add inside `ClientProtocol` (after `serviceReady`):

```swift
    /// Opfilter calls this to request a Touch ID authorization decision from
    /// the GUI. The GUI must respond with `true` (allow and open a session)
    /// or `false` (deny) within `remainingSeconds`, otherwise opfilter fails
    /// closed when the ES deadline elapses.
    func requestAuthorization(
        processName: String,
        signingID: String,
        pid: Int,
        pidVersion: UInt32,
        path: String,
        isWrite: Bool,
        remainingSeconds: Double,
        withReply reply: @escaping (Bool) -> Void
    )
```

- [ ] **Step 4.2: Add a deny-by-default stub in XPCClient**

In `clearancekit/App/XPCClient.swift`, add to the `XPCClient` class (near the other `ClientProtocol` conformance methods):

```swift
    func requestAuthorization(
        processName: String,
        signingID: String,
        pid: Int,
        pidVersion: UInt32,
        path: String,
        isWrite: Bool,
        remainingSeconds: Double,
        withReply reply: @escaping (Bool) -> Void
    ) {
        // Stub — replaced by AuthorizationRequestWindow routing in Task 9.
        reply(false)
    }
```

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: `** TEST SUCCEEDED **` (no new tests; compile is the test).

- [ ] **Step 4.3: Commit**

```bash
git add Shared/XPCProtocol.swift clearancekit/App/XPCClient.swift
git commit -m "$(cat <<'EOF'
Add requestAuthorization to ClientProtocol

Introduces a reply-bearing XPC method the opfilter uses to obtain a
Touch ID decision from the GUI. XPCClient ships a deny-by-default stub
— the routing to AuthorizationRequestWindow lands once that window
exists.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: AuthorizationGate — XPC dispatch and deadline timer

**Files:**
- `opfilter/XPC/AuthorizationGate.swift` (edit)
- `opfilter/XPC/EventBroadcaster.swift` (edit)
- `Tests/AuthorizationGateDispatchTests.swift` (new)

- [ ] **Step 5.1: Write dispatch tests first (RED)**

Create `Tests/AuthorizationGateDispatchTests.swift`:

```swift
//
//  AuthorizationGateDispatchTests.swift
//  clearancekitTests
//

import Foundation
import Testing
@testable import opfilter

@Suite("AuthorizationGate dispatch")
struct AuthorizationGateDispatchTests {
    @Test("allow response opens a session and responds true")
    func allowOpensSession() async {
        let gate = AuthorizationGate()
        let broadcaster = FakeBroadcaster(answer: true)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let respondedAllowed = OSAllocatedUnfairLock(initialState: false)

        let event = makeEvent(
            deadlineMsFromNow: 5000,
            respond: { allowed, _ in
                respondedAllowed.withLock { $0 = allowed }
                postRespondCalled.signal()
            }
        )

        gate.requestAuthorization(
            event: event,
            sessionDuration: 300,
            broadcaster: broadcaster,
            postRespond: { _, _, _, _ in }
        )

        _ = postRespondCalled.wait(timeout: .now() + .seconds(2))
        #expect(respondedAllowed.withLock { $0 } == true)
        #expect(gate.hasActiveSession(
            pid: event.processID,
            pidVersion: event.processIdentity.pidVersion,
            prefix: event.path
        ) == true)
    }

    @Test("deny response does not open a session")
    func denyLeavesStoreEmpty() async {
        let gate = AuthorizationGate()
        let broadcaster = FakeBroadcaster(answer: false)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let respondedAllowed = OSAllocatedUnfairLock(initialState: true)

        let event = makeEvent(
            deadlineMsFromNow: 5000,
            respond: { allowed, _ in
                respondedAllowed.withLock { $0 = allowed }
                postRespondCalled.signal()
            }
        )

        gate.requestAuthorization(
            event: event,
            sessionDuration: 300,
            broadcaster: broadcaster,
            postRespond: { _, _, _, _ in }
        )

        _ = postRespondCalled.wait(timeout: .now() + .seconds(2))
        #expect(respondedAllowed.withLock { $0 } == false)
        #expect(gate.hasActiveSession(
            pid: event.processID,
            pidVersion: event.processIdentity.pidVersion,
            prefix: event.path
        ) == false)
    }

    @Test("no GUI client — denies without opening a session")
    func withoutClientDenies() async {
        let gate = AuthorizationGate()
        let broadcaster = FakeBroadcaster(answer: nil)  // no client
        let postRespondCalled = DispatchSemaphore(value: 0)
        let respondedAllowed = OSAllocatedUnfairLock(initialState: true)

        let event = makeEvent(
            deadlineMsFromNow: 5000,
            respond: { allowed, _ in
                respondedAllowed.withLock { $0 = allowed }
                postRespondCalled.signal()
            }
        )

        gate.requestAuthorization(
            event: event,
            sessionDuration: 300,
            broadcaster: broadcaster,
            postRespond: { _, _, _, _ in }
        )

        _ = postRespondCalled.wait(timeout: .now() + .seconds(2))
        #expect(respondedAllowed.withLock { $0 } == false)
    }

    // MARK: helpers

    private func makeEvent(
        deadlineMsFromNow: UInt64,
        respond: @escaping @Sendable (Bool, Bool) -> Void
    ) -> FileAuthEvent {
        let timebase: mach_timebase_info_data_t = {
            var info = mach_timebase_info_data_t(); mach_timebase_info(&info); return info
        }()
        let nanos = deadlineMsFromNow * 1_000_000
        let ticks = nanos * UInt64(timebase.denom) / UInt64(timebase.numer)
        let deadline = mach_absolute_time() + ticks
        return FileAuthEvent(
            correlationID: UUID(), operation: .open, accessKind: .write,
            path: "/Secrets", secondaryPath: nil,
            processIdentity: ProcessIdentity(pid: 1234, pidVersion: 7),
            processID: 1234, parentPID: 1, processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            uid: 501, gid: 20, ttyPath: nil, deadline: deadline, respond: respond
        )
    }
}

private final class FakeBroadcaster: AuthorizationBroadcasting, @unchecked Sendable {
    let answer: Bool?
    init(answer: Bool?) { self.answer = answer }

    func requestAuthorizationFromFirstClient(
        processName: String, signingID: String, pid: Int, pidVersion: UInt32,
        path: String, isWrite: Bool, remainingSeconds: Double,
        reply: @escaping (Bool) -> Void
    ) {
        guard let answer else { reply(false); return }
        DispatchQueue.global().async { reply(answer) }
    }
}
```

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: build fails — `requestAuthorization` on the gate and `AuthorizationBroadcasting` do not exist.

- [ ] **Step 5.2: Define the broadcaster seam and extend EventBroadcaster**

In `opfilter/XPC/AuthorizationGate.swift`, add the protocol near the top (the consumer lives in the same folder as the type that takes it — see CLAUDE.md protocol placement rule):

```swift
protocol AuthorizationBroadcasting: AnyObject, Sendable {
    func requestAuthorizationFromFirstClient(
        processName: String,
        signingID: String,
        pid: Int,
        pidVersion: UInt32,
        path: String,
        isWrite: Bool,
        remainingSeconds: Double,
        reply: @escaping (Bool) -> Void
    )
}
```

In `opfilter/XPC/EventBroadcaster.swift`, add the conformance and method:

```swift
extension EventBroadcaster: AuthorizationBroadcasting {
    func requestAuthorizationFromFirstClient(
        processName: String,
        signingID: String,
        pid: Int,
        pidVersion: UInt32,
        path: String,
        isWrite: Bool,
        remainingSeconds: Double,
        reply: @escaping (Bool) -> Void
    ) {
        let connection = storage.withLock { $0.guiClients.values.first }
        guard let connection else {
            reply(false)
            return
        }
        let replyBox = OSAllocatedUnfairLock(initialState: false)
        let safeReply: (Bool) -> Void = { allowed in
            let alreadyCalled = replyBox.withLock { called -> Bool in
                if called { return true }
                called = true
                return false
            }
            guard !alreadyCalled else { return }
            reply(allowed)
        }
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
            safeReply(false)
        } as? ClientProtocol
        guard let proxy else {
            safeReply(false)
            return
        }
        proxy.requestAuthorization(
            processName: processName,
            signingID: signingID,
            pid: pid,
            pidVersion: pidVersion,
            path: path,
            isWrite: isWrite,
            remainingSeconds: remainingSeconds,
            withReply: safeReply
        )
    }
}
```

Note: `storage` is `private` on the class; since this extension lives in the same file it can read it. If the extension is placed in a different file, `storage` must be relaxed to `fileprivate` — keep both in the same file to avoid that.

Actually keep the extension in `EventBroadcaster.swift` as shown above.

- [ ] **Step 5.3: Add the dispatch method on AuthorizationGate**

Append to `opfilter/XPC/AuthorizationGate.swift`:

```swift
extension AuthorizationGate {
    func requestAuthorization(
        event: FileAuthEvent,
        sessionDuration: TimeInterval,
        broadcaster: AuthorizationBroadcasting,
        postRespond: @escaping @Sendable (FileAuthEvent, PolicyDecision, [AncestorInfo], UInt64) -> Void
    ) {
        let remainingMs = MachTime.millisecondsToDeadline(event.deadline)
        let remainingSeconds = max(0.0, Double(remainingMs) / 1000.0 - 0.1)

        let responded = OSAllocatedUnfairLock(initialState: false)
        let gate = self

        let respondOnce: @Sendable (Bool) -> Void = { allowed in
            let skip = responded.withLock { state -> Bool in
                if state { return true }
                state = true
                return false
            }
            guard !skip else { return }
            if allowed {
                gate.createSession(
                    pid: event.processID,
                    pidVersion: event.processIdentity.pidVersion,
                    prefix: event.path,
                    duration: sessionDuration
                )
            }
            event.respond(allowed, false)
            let decision: PolicyDecision = allowed
                ? .allowed(
                    ruleID: UUID(),
                    ruleName: event.path,
                    ruleSource: .user,
                    matchedCriterion: "Touch ID authorized"
                )
                : .denied(
                    ruleID: UUID(),
                    ruleName: event.path,
                    ruleSource: .user,
                    allowedCriteria: "Touch ID required"
                )
            postRespond(event, decision, [], 0)
        }

        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
        timer.schedule(deadline: .now() + remainingSeconds)
        timer.setEventHandler {
            respondOnce(false)
            timer.cancel()
        }
        timer.resume()

        broadcaster.requestAuthorizationFromFirstClient(
            processName: event.processPath,
            signingID: event.signingID,
            pid: Int(event.processID),
            pidVersion: event.processIdentity.pidVersion,
            path: event.path,
            isWrite: event.accessKind == .write,
            remainingSeconds: remainingSeconds
        ) { allowed in
            timer.cancel()
            respondOnce(allowed)
        }
    }
}
```

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: `** TEST SUCCEEDED **`.

- [ ] **Step 5.4: Commit**

```bash
git add opfilter/XPC/AuthorizationGate.swift opfilter/XPC/EventBroadcaster.swift Tests/AuthorizationGateDispatchTests.swift
git commit -m "$(cat <<'EOF'
Add AuthorizationGate XPC dispatch with deadline-bounded reply

AuthorizationGate now drives the GUI via an AuthorizationBroadcasting
seam (implemented by EventBroadcaster). A deadline-safe dispatch timer
fails closed slightly before the ES deadline, and a once-only latch
prevents duplicate responds if the GUI reply and the timer race.
Allow responses open a session; denies leave the store untouched.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: FileAuthPipeline + FAAFilterInteractor — wire the authorization path

**Files:**
- `opfilter/Filter/FileAuthPipeline.swift` (edit)
- `opfilter/main.swift` (edit)
- `Tests/FileAuthPipelineTests.swift` (edit — adapt existing constructor calls)
- `Tests/FAAFilterInteractorTests.swift` (edit — adapt existing constructor calls)
- `Tests/FileAuthPipelineAuthorizationTests.swift` (new)

- [ ] **Step 6.1: Write a session-hit test (RED)**

Create `Tests/FileAuthPipelineAuthorizationTests.swift`:

```swift
//
//  FileAuthPipelineAuthorizationTests.swift
//  clearancekitTests
//

import Foundation
import Testing
@testable import opfilter

@Suite("FileAuthPipeline authorization routing")
struct FileAuthPipelineAuthorizationTests {
    @Test("active session short-circuits the authorization handler")
    func activeSessionAllowsWithoutPrompt() async {
        let gate = AuthorizationGate()
        gate.createSession(pid: 4242, pidVersion: 3, prefix: "/Secrets", duration: 60)
        let processTree = FakeProcessTree()
        let authorizationCalled = OSAllocatedUnfairLock(initialState: false)
        let postRespondCalled = DispatchSemaphore(value: 0)
        let respondedAllowed = OSAllocatedUnfairLock(initialState: false)

        let rule = FAARule(
            protectedPathPrefix: "/Secrets",
            requiresAuthorization: true
        )

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [rule] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, decision, _, _ in
                respondedAllowed.withLock { $0 = decision.isAllowed }
                postRespondCalled.signal()
            },
            authorizationGate: gate,
            authorizationHandler: { _, _ in
                authorizationCalled.withLock { $0 = true }
            }
        )
        pipeline.start()

        let respondSignal = DispatchSemaphore(value: 0)
        let event = FileAuthEvent(
            correlationID: UUID(), operation: .open, accessKind: .write,
            path: "/Secrets/file.txt", secondaryPath: nil,
            processIdentity: ProcessIdentity(pid: 4242, pidVersion: 3),
            processID: 4242, parentPID: 1, processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            uid: 501, gid: 20, ttyPath: nil,
            deadline: mach_absolute_time() + 5_000_000_000,
            respond: { _, _ in respondSignal.signal() }
        )
        pipeline.submit(event)

        _ = postRespondCalled.wait(timeout: .now() + .seconds(2))
        #expect(respondedAllowed.withLock { $0 } == true)
        #expect(authorizationCalled.withLock { $0 } == false)
    }

    @Test("no session — authorization handler is invoked")
    func noSessionDelegatesToHandler() async {
        let gate = AuthorizationGate()
        let processTree = FakeProcessTree()
        let handlerCalled = DispatchSemaphore(value: 0)
        let capturedDuration = OSAllocatedUnfairLock<TimeInterval>(initialState: 0)

        let rule = FAARule(
            protectedPathPrefix: "/Secrets",
            requiresAuthorization: true,
            authorizationSessionDuration: 900
        )

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [rule] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in },
            authorizationGate: gate,
            authorizationHandler: { _, duration in
                capturedDuration.withLock { $0 = duration }
                handlerCalled.signal()
            }
        )
        pipeline.start()

        let event = FileAuthEvent(
            correlationID: UUID(), operation: .open, accessKind: .write,
            path: "/Secrets/file.txt", secondaryPath: nil,
            processIdentity: ProcessIdentity(pid: 5555, pidVersion: 1),
            processID: 5555, parentPID: 1, processPath: "/Apps/Example",
            teamID: "ABCDE12345", signingID: "com.example.app",
            uid: 501, gid: 20, ttyPath: nil,
            deadline: mach_absolute_time() + 5_000_000_000,
            respond: { _, _ in }
        )
        pipeline.submit(event)

        _ = handlerCalled.wait(timeout: .now() + .seconds(2))
        #expect(capturedDuration.withLock { $0 } == 900)
    }
}

private final class FakeProcessTree: ProcessTreeProtocol, @unchecked Sendable {
    func record(for identity: ProcessIdentity) -> ESProcessRecord? { nil }
    func ancestors(of identity: ProcessIdentity) -> [AncestorInfo] { [] }
    func contains(identity: ProcessIdentity) -> Bool { true }
}
```

Note: adapt `FakeProcessTree` to whatever `ProcessTreeProtocol` methods exist at the time of writing; read the protocol declaration first and implement only its members.

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: build fails — the new init parameters do not exist.

- [ ] **Step 6.2: Extend FileAuthPipeline (GREEN)**

Edit `opfilter/Filter/FileAuthPipeline.swift`.

Add stored properties next to the other privates:

```swift
    private let authorizationGate: AuthorizationGate
    private let authorizationHandler: @Sendable (FileAuthEvent, TimeInterval) -> Void
```

Add the two parameters to `init` with sensible defaults so existing call sites in tests that don't care about authorization keep compiling:

```swift
    init(
        processTree: ProcessTreeProtocol,
        rulesProvider: @escaping @Sendable () -> [FAARule],
        allowlistProvider: @escaping @Sendable () -> [AllowlistEntry],
        ancestorAllowlistProvider: @escaping @Sendable () -> [AncestorAllowlistEntry],
        postRespond: @escaping @Sendable (FileAuthEvent, PolicyDecision, [AncestorInfo], UInt64) -> Void,
        authorizationGate: AuthorizationGate = AuthorizationGate(),
        authorizationHandler: @escaping @Sendable (FileAuthEvent, TimeInterval) -> Void = { _, _ in },
        eventBufferCapacity: Int = 1024,
        slowQueueCapacity: Int = 256,
        hotPathQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.hot", qos: .userInteractive),
        slowWorkerQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.pipeline.slow", qos: .userInitiated, attributes: .concurrent),
        slowWorkerSemaphore: DispatchSemaphore = DispatchSemaphore(value: 2),
        eventSignal: DispatchSemaphore = DispatchSemaphore(value: 0),
        slowSignal: DispatchSemaphore = DispatchSemaphore(value: 0)
    ) {
        self.eventBuffer = BoundedQueue(capacity: eventBufferCapacity)
        self.slowQueue = BoundedQueue(capacity: slowQueueCapacity)
        self.processTree = processTree
        self.rulesProvider = rulesProvider
        self.allowlistProvider = allowlistProvider
        self.ancestorAllowlistProvider = ancestorAllowlistProvider
        self.postRespondHandler = postRespond
        self.authorizationGate = authorizationGate
        self.authorizationHandler = authorizationHandler
        self.hotPathQueue = hotPathQueue
        self.slowWorkerQueue = slowWorkerQueue
        self.slowWorkerSemaphore = slowWorkerSemaphore
        self.eventSignal = eventSignal
        self.slowSignal = slowSignal
        self.metricsStorage = OSAllocatedUnfairLock(initialState: PipelineMetrics())
    }
```

Insert an authorization-handling helper and use it both in `processHotPath` (for `.processLevelOnly`) and `processSlowPath` (for `.ancestryRequired`). First add the helper below `processSlowPath`:

```swift
    private func handleDecisionWithAuthorization(
        _ decision: PolicyDecision,
        event: FileAuthEvent,
        ancestors: [AncestorInfo],
        dwellNanoseconds: UInt64
    ) -> Bool {
        guard case .requiresAuthorization(let ruleID, let ruleName, let ruleSource, _, let duration) = decision else {
            return false
        }
        if authorizationGate.hasActiveSession(
            pid: event.processID,
            pidVersion: event.processIdentity.pidVersion,
            prefix: ruleName
        ) {
            authorizationGate.touchSession(
                pid: event.processID,
                pidVersion: event.processIdentity.pidVersion,
                prefix: ruleName
            )
            let sessionDecision = PolicyDecision.allowed(
                ruleID: ruleID,
                ruleName: ruleName,
                ruleSource: ruleSource,
                matchedCriterion: "authorized session"
            )
            event.respond(true, false)
            postRespondHandler(event, sessionDecision, ancestors, dwellNanoseconds)
            return true
        }
        authorizationHandler(event, duration)
        return true
    }
```

In `processHotPath`, replace the `.processLevelOnly where ancestorAllowlist.isEmpty` block with:

```swift
        case .processLevelOnly where ancestorAllowlist.isEmpty:
            let decision = evaluateAccess(
                rules: rules, allowlist: allowlist, ancestorAllowlist: [],
                path: event.path, secondaryPath: event.secondaryPath, processPath: event.processPath,
                teamID: event.teamID, signingID: event.signingID,
                accessKind: event.accessKind,
                ancestors: []
            )
            let ancestors = processTree.ancestors(of: event.processIdentity)
            if handleDecisionWithAuthorization(decision, event: event, ancestors: ancestors, dwellNanoseconds: 0) {
                metricsStorage.withLock { $0.hotPathRespondedCount += 1 }
                return
            }
            event.respond(decision.isAllowed, false)
            metricsStorage.withLock { $0.hotPathRespondedCount += 1 }
            postRespondHandler(event, decision, ancestors, 0)
```

In `processSlowPath`, replace the tail:

```swift
        event.respond(decision.isAllowed, false)
        let logAncestors = processTree.ancestors(of: event.processIdentity)
        postRespondHandler(event, decision, logAncestors, dwellNanoseconds)
```

with:

```swift
        let logAncestors = processTree.ancestors(of: event.processIdentity)
        if handleDecisionWithAuthorization(decision, event: event, ancestors: logAncestors, dwellNanoseconds: dwellNanoseconds) {
            return
        }
        event.respond(decision.isAllowed, false)
        postRespondHandler(event, decision, logAncestors, dwellNanoseconds)
```

- [ ] **Step 6.3: Wire main.swift to the broadcaster-backed handler**

In `opfilter/main.swift`, immediately before the `let pipeline = FileAuthPipeline(...)` line construct a shared gate and locate the XPC server's broadcaster. The server already owns an `EventBroadcaster`; expose it with a `broadcaster: EventBroadcaster` accessor on `XPCServer` if one is not already public.

Replace the existing `FileAuthPipeline` construction block with:

```swift
let authorizationGate = AuthorizationGate()
let authorizationBroadcaster: AuthorizationBroadcasting = server.broadcaster

let pipeline = FileAuthPipeline(
    processTree: processTree,
    rulesProvider: { faaInteractorRef.value?.currentRules() ?? [] },
    allowlistProvider: { allowlistState.currentAllowlist() },
    ancestorAllowlistProvider: { allowlistState.currentAncestorAllowlist() },
    postRespond: { event, decision, ancestors, dwell in
        postRespondHandler.postRespond(fileEvent: event, decision: decision, ancestors: ancestors, dwellNanoseconds: dwell)
    },
    authorizationGate: authorizationGate,
    authorizationHandler: { event, duration in
        authorizationGate.requestAuthorization(
            event: event,
            sessionDuration: duration,
            broadcaster: authorizationBroadcaster,
            postRespond: { evt, decision, ancestors, dwell in
                postRespondHandler.postRespond(fileEvent: evt, decision: decision, ancestors: ancestors, dwellNanoseconds: dwell)
            }
        )
    },
    hotPathQueue: hotPathQueue,
    slowWorkerQueue: slowWorkerQueue,
    slowWorkerSemaphore: slowWorkerSemaphore,
    eventSignal: eventSignal,
    slowSignal: slowSignal
)
```

If `XPCServer` does not already expose `broadcaster`, add `public let broadcaster: EventBroadcaster` (or equivalent read-only accessor) in `opfilter/XPC/XPCServer.swift` and set it in its init.

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: `** TEST SUCCEEDED **`.

- [ ] **Step 6.4: Commit**

```bash
git add opfilter/Filter/FileAuthPipeline.swift opfilter/main.swift opfilter/XPC/XPCServer.swift Tests/FileAuthPipelineAuthorizationTests.swift
git commit -m "$(cat <<'EOF'
Route requiresAuthorization decisions through AuthorizationGate

FileAuthPipeline now carries an AuthorizationGate and an authorizationHandler
closure. Both the hot path and the slow path short-circuit to an "authorized
session" allow when a matching session exists, otherwise they hand the event
to the handler. main.swift wires the handler to AuthorizationGate's XPC
dispatch against the XPCServer's broadcaster.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: GUI — RuleEditView gains the three new fields

**Files:**
- `clearancekit/Configure/Policy/RuleEditView.swift` (edit)

- [ ] **Step 7.1: Extend DraftRule**

In `RuleEditView.swift`, extend the private `DraftRule` struct:

```swift
private struct DraftRule {
    var protectedPathPrefix: String = ""
    var allowedProcessPaths: [String] = []
    var allowedSignatures: [String] = []
    var allowedAncestorProcessPaths: [String] = []
    var allowedAncestorSignatures: [String] = []
    var enforceOnWriteOnly: Bool = false
    var requireValidSigning: Bool = false
    var authorizedSignatures: [String] = []
    var requiresAuthorization: Bool = false
    var authorizationSessionDuration: TimeInterval = 300

    init() {}

    init(from rule: FAARule) {
        self.protectedPathPrefix = rule.protectedPathPrefix
        self.allowedProcessPaths = rule.allowedProcessPaths
        self.allowedSignatures = rule.allowedSignatures.map(\.description)
        self.allowedAncestorProcessPaths = rule.allowedAncestorProcessPaths
        self.allowedAncestorSignatures = rule.allowedAncestorSignatures.map(\.description)
        self.enforceOnWriteOnly = rule.enforceOnWriteOnly
        self.requireValidSigning = rule.requireValidSigning
        self.authorizedSignatures = rule.authorizedSignatures.map(\.description)
        self.requiresAuthorization = rule.requiresAuthorization
        self.authorizationSessionDuration = rule.authorizationSessionDuration
    }

    func toRule(preservingID id: UUID?) -> FAARule {
        let trimmed: (String) -> String = { $0.trimmingCharacters(in: .whitespaces) }
        let nonEmpty: ([String]) -> [String] = { $0.map(trimmed).filter { !$0.isEmpty } }
        let parseSignature: (String) -> ProcessSignature? = { s in
            guard let colonIndex = s.firstIndex(of: ":") else { return nil }
            return ProcessSignature(
                teamID: String(s[s.startIndex..<colonIndex]),
                signingID: String(s[s.index(after: colonIndex)...])
            )
        }
        return FAARule(
            id: id ?? UUID(),
            protectedPathPrefix: trimmed(protectedPathPrefix),
            allowedProcessPaths: nonEmpty(allowedProcessPaths),
            allowedSignatures: nonEmpty(allowedSignatures).compactMap(parseSignature),
            allowedAncestorProcessPaths: nonEmpty(allowedAncestorProcessPaths),
            allowedAncestorSignatures: nonEmpty(allowedAncestorSignatures).compactMap(parseSignature),
            enforceOnWriteOnly: enforceOnWriteOnly,
            requireValidSigning: requireValidSigning,
            authorizedSignatures: nonEmpty(authorizedSignatures).compactMap(parseSignature),
            requiresAuthorization: requiresAuthorization,
            authorizationSessionDuration: authorizationSessionDuration
        )
    }
}
```

- [ ] **Step 7.2: Add the three new sections to the form**

Add a new picker-target case at the top of the file:

```swift
private enum ProcessPickerTarget: Identifiable, Hashable {
    case process
    case signature
    case ancestor
    case ancestorSignature
    case authorizedSignature
    var id: Self { self }
}
```

In `body`, insert these sections between the `requireValidSigning` section and `.formStyle(.grouped)`:

```swift
                Section {
                    StringListEditor(values: $draft.authorizedSignatures, placeholder: "teamID:signingID")
                } header: {
                    pickerSectionHeader("Require Touch ID", target: .authorizedSignature)
                } footer: {
                    Text("Matching processes prompt for Touch ID. A successful prompt opens a session so further accesses do not re-prompt.")
                        .foregroundStyle(.secondary)
                }

                Section {
                    Toggle("Require Touch ID for all valid signers", isOn: $draft.requiresAuthorization)
                } footer: {
                    Text("Any process with a valid code signature will be prompted for Touch ID. Unsigned processes are still denied outright.")
                        .foregroundStyle(.secondary)
                }

                if !draft.authorizedSignatures.isEmpty || draft.requiresAuthorization {
                    Section("Session inactivity") {
                        Picker("Duration", selection: $draft.authorizationSessionDuration) {
                            Text("1 minute").tag(TimeInterval(60))
                            Text("5 minutes").tag(TimeInterval(300))
                            Text("15 minutes").tag(TimeInterval(900))
                            Text("1 hour").tag(TimeInterval(3600))
                            Text("Custom").tag(TimeInterval(-1))
                        }
                        if draft.authorizationSessionDuration == -1 {
                            TextField("Seconds", value: $draft.authorizationSessionDuration, format: .number)
                        }
                    }
                }
```

Extend the `processPicker` sheet handler to route `.authorizedSignature`:

```swift
                case .authorizedSignature:
                    draft.authorizedSignatures.append(sig)
```

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: `** TEST SUCCEEDED **`.

- [ ] **Step 7.3: Commit**

```bash
git add clearancekit/Configure/Policy/RuleEditView.swift
git commit -m "$(cat <<'EOF'
Add Touch ID authorization fields to RuleEditView

DraftRule carries authorizedSignatures, requiresAuthorization and
authorizationSessionDuration. The form exposes a signature list editor,
a catch-all toggle for valid signers, and a session duration picker
with preset 1m/5m/15m/1h plus a custom field.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: GUI — AuthorizationRequestWindow

**Files:**
- `clearancekit/Authorization/AuthorizationRequestWindow.swift` (new)

- [ ] **Step 8.1: Create the window**

Create `clearancekit/Authorization/AuthorizationRequestWindow.swift`:

```swift
//
//  AuthorizationRequestWindow.swift
//  clearancekit
//

import AppKit
import LocalAuthentication
import SwiftUI

@MainActor
final class AuthorizationRequestWindow: NSObject {
    static let shared = AuthorizationRequestWindow()

    struct AuthRequest {
        let processName: String
        let signingID: String
        let path: String
        let isWrite: Bool
        let remainingSeconds: Double
        let reply: (Bool) -> Void
    }

    private var panel: NSPanel?
    private var pendingRequests: [AuthRequest] = []
    private var countdownTimer: Timer?
    private var currentDeadline: Date?
    private var countdownLabel: NSTextField?

    func enqueue(_ request: AuthRequest) {
        pendingRequests.append(request)
        if panel == nil {
            showNext()
        }
    }

    private func showNext() {
        guard let request = pendingRequests.first else { return }
        currentDeadline = Date().addingTimeInterval(request.remainingSeconds)

        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 420, height: 200),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        panel.level = .floating
        panel.title = "ClearanceKit Authorization"
        panel.isReleasedWhenClosed = false

        let container = NSStackView()
        container.orientation = .vertical
        container.alignment = .leading
        container.spacing = 12
        container.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        container.translatesAutoresizingMaskIntoConstraints = false

        let headline = NSTextField(labelWithString: "\(request.isWrite ? "Write" : "Read") access to \(request.path)")
        headline.font = NSFont.systemFont(ofSize: 14, weight: .semibold)
        headline.lineBreakMode = .byTruncatingMiddle
        container.addArrangedSubview(headline)

        let subline = NSTextField(labelWithString: "Requested by \(request.processName)")
        subline.textColor = .secondaryLabelColor
        container.addArrangedSubview(subline)

        let signatureLine = NSTextField(labelWithString: "Signing ID: \(request.signingID)")
        signatureLine.textColor = .secondaryLabelColor
        signatureLine.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        container.addArrangedSubview(signatureLine)

        let countdown = NSTextField(labelWithString: "")
        countdown.textColor = .tertiaryLabelColor
        container.addArrangedSubview(countdown)
        self.countdownLabel = countdown

        panel.contentView = container
        panel.makeKeyAndOrderFront(nil)
        self.panel = panel

        startCountdown()
        runBiometrics(for: request)
    }

    private func startCountdown() {
        countdownTimer?.invalidate()
        countdownTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.updateCountdown()
            }
        }
    }

    private func updateCountdown() {
        guard let deadline = currentDeadline else { return }
        let remaining = deadline.timeIntervalSinceNow
        if remaining <= 0 {
            countdownLabel?.stringValue = "Timed out"
            finish(allowed: false)
            return
        }
        countdownLabel?.stringValue = String(format: "%.1fs remaining", remaining)
    }

    private func runBiometrics(for request: AuthRequest) {
        let context = LAContext()
        let reason = "Authorize \(request.isWrite ? "write" : "read") access to \(request.path)"
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { [weak self] success, _ in
            Task { @MainActor in
                self?.finish(allowed: success)
            }
        }
    }

    private func finish(allowed: Bool) {
        guard let request = pendingRequests.first else { return }
        pendingRequests.removeFirst()
        countdownTimer?.invalidate()
        countdownTimer = nil
        panel?.orderOut(nil)
        panel = nil
        currentDeadline = nil
        countdownLabel = nil
        request.reply(allowed)
        if !pendingRequests.isEmpty {
            showNext()
        }
    }
}
```

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: `** TEST SUCCEEDED **` (compile check; no direct tests for this AppKit type).

- [ ] **Step 8.2: Commit**

```bash
git add clearancekit/Authorization/AuthorizationRequestWindow.swift
git commit -m "$(cat <<'EOF'
Add AuthorizationRequestWindow for Touch ID prompts

Floating NSPanel with a live countdown label and LAContext
deviceOwnerAuthentication. Pending requests are queued so a second
prompt lines up behind the first instead of fighting for focus.
Timing out or cancelling replies false; biometric success replies true.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: GUI — XPCClient routes requestAuthorization to the window

**Files:**
- `clearancekit/App/XPCClient.swift` (edit — replace stub)

- [ ] **Step 9.1: Replace the stub**

In `clearancekit/App/XPCClient.swift`, replace the stub added in Task 4:

```swift
    func requestAuthorization(
        processName: String,
        signingID: String,
        pid: Int,
        pidVersion: UInt32,
        path: String,
        isWrite: Bool,
        remainingSeconds: Double,
        withReply reply: @escaping (Bool) -> Void
    ) {
        Task { @MainActor in
            let request = AuthorizationRequestWindow.AuthRequest(
                processName: processName,
                signingID: signingID,
                path: path,
                isWrite: isWrite,
                remainingSeconds: remainingSeconds,
                reply: reply
            )
            AuthorizationRequestWindow.shared.enqueue(request)
        }
    }
```

Run: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5`
Expected: `** TEST SUCCEEDED **`.

- [ ] **Step 9.2: Commit**

```bash
git add clearancekit/App/XPCClient.swift
git commit -m "$(cat <<'EOF'
Route opfilter authorization requests to AuthorizationRequestWindow

Replaces the deny-by-default stub. The XPC reply closure is forwarded
to the window and invoked exactly once — either on biometric success,
on cancel, or on countdown timeout.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Verification

After all nine tasks are committed:

- [ ] Run the full test suite: `xcodebuild test -scheme clearancekitTests 2>&1 | tail -5` — expect `** TEST SUCCEEDED **`.
- [ ] Manual smoke: create a rule with `requiresAuthorization: true` on a writable folder, attempt a write from TextEdit, confirm the Touch ID panel appears, confirm a successful Touch ID opens a session such that a second write within 5 minutes does not re-prompt.
- [ ] Confirm legacy user databases still load and verify — `FAARule.encode(to:)` omits the three new keys when they hold defaults, so canonical JSON for existing rules remains byte-identical.
