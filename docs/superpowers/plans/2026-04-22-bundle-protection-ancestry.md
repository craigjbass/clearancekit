# Bundle Protection Ancestry Trust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow bundle writes from sub-processes spawned by trusted updaters or the bundle's own team, by checking process ancestry in `BundleProtectionEvaluator`.

**Architecture:** Add a `matches(teamID:signingID:)` helper to `BundleUpdaterSignature` (with wildcard support), extend `BundleProtectionEvaluator.evaluate()` to accept `[AncestorInfo]`, then wire the already-available `ancestors` from the slow path in `FileAuthPipeline`.

**Tech Stack:** Swift, Swift Testing (`@Suite`/`@Test`/`#expect`), xcodebuild

---

### Task 1: Add `matches(teamID:signingID:)` to `BundleUpdaterSignature`

**Files:**
- Create: `Tests/BundleUpdaterSignatureTests.swift`
- Modify: `Shared/BundleUpdaterSignature.swift`

- [ ] **Step 1: Write the failing tests**

Create `Tests/BundleUpdaterSignatureTests.swift`:

```swift
//
//  BundleUpdaterSignatureTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("BundleUpdaterSignature")
struct BundleUpdaterSignatureTests {

    @Test("exact match returns true")
    func exactMatchReturnsTrue() {
        let sig = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle")
        #expect(sig.matches(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle"))
    }

    @Test("wrong teamID returns false")
    func wrongTeamIDReturnsFalse() {
        let sig = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle")
        #expect(!sig.matches(teamID: "OTHER", signingID: "org.sparkle-project.Sparkle"))
    }

    @Test("wrong signingID returns false")
    func wrongSigningIDReturnsFalse() {
        let sig = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle")
        #expect(!sig.matches(teamID: "SPARKLE", signingID: "org.sparkle-project.OtherTool"))
    }

    @Test("wildcard signingID matches any signing ID from the same team")
    func wildcardSigningIDMatchesAnySigningID() {
        let sig = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "*")
        #expect(sig.matches(teamID: "SPARKLE", signingID: "org.sparkle-project.Downloader"))
        #expect(sig.matches(teamID: "SPARKLE", signingID: "org.sparkle-project.Installer"))
    }

    @Test("wildcard signingID does not match different team")
    func wildcardSigningIDDoesNotMatchDifferentTeam() {
        let sig = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "*")
        #expect(!sig.matches(teamID: "OTHER", signingID: "org.sparkle-project.Sparkle"))
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/BundleUpdaterSignatureTests 2>&1 | grep -E "error:|FAILED|passed|failed"
```

Expected: compile error — `value of type 'BundleUpdaterSignature' has no member 'matches'`

- [ ] **Step 3: Add `matches()` to `BundleUpdaterSignature`**

In `Shared/BundleUpdaterSignature.swift`, add after the `init`:

```swift
public func matches(teamID: String, signingID: String) -> Bool {
    self.teamID == teamID && (self.signingID == "*" || self.signingID == signingID)
}
```

Full file after change:

```swift
//
//  BundleUpdaterSignature.swift
//  clearancekit
//

import Foundation

public struct BundleUpdaterSignature: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public let teamID: String
    public let signingID: String

    public init(id: UUID = UUID(), teamID: String, signingID: String) {
        self.id = id
        self.teamID = teamID
        self.signingID = signingID
    }

    public func matches(teamID: String, signingID: String) -> Bool {
        self.teamID == teamID && (self.signingID == "*" || self.signingID == signingID)
    }
}
```

- [ ] **Step 4: Run to verify tests pass**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/BundleUpdaterSignatureTests 2>&1 | grep -E "error:|FAILED|passed|failed"
```

Expected: `Test Suite 'BundleUpdaterSignatureTests' passed`

- [ ] **Step 5: Commit**

```bash
git add Shared/BundleUpdaterSignature.swift Tests/BundleUpdaterSignatureTests.swift
git commit -m "feat: add wildcard-aware matches() to BundleUpdaterSignature"
```

---

### Task 2: Add ancestry checks to `BundleProtectionEvaluator`

**Files:**
- Modify: `opfilter/Filter/BundleProtectionEvaluator.swift`
- Modify: `Tests/BundleProtectionEvaluatorTests.swift`

- [ ] **Step 1: Add `ancestors` param to `evaluate()` and update tests**

This is a compile-fix + new failing test step combined. Replace the entire contents of `Tests/BundleProtectionEvaluatorTests.swift`:

```swift
//
//  BundleProtectionEvaluatorTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("BundleProtectionEvaluator")
struct BundleProtectionEvaluatorTests {

    private func makeCache(teamID: String = "TEAM123") -> BundleCodesignCache {
        BundleCodesignCache(
            ttl: 60,
            executableEnumerator: { _ in ["/fake/App.app/Contents/MacOS/App"] },
            signatureReader: { _ in teamID }
        )
    }

    private func makeEvaluator(
        cache: BundleCodesignCache,
        updaters: [BundleUpdaterSignature] = []
    ) -> BundleProtectionEvaluator {
        BundleProtectionEvaluator(cache: cache, updaterSignaturesProvider: { updaters })
    }

    private func ancestor(teamID: String, signingID: String) -> AncestorInfo {
        AncestorInfo(path: "/fake/path", teamID: teamID, signingID: signingID)
    }

    // MARK: - isBundleWrite

    @Test("non-bundle write path returns false from isBundleWrite")
    func nonBundleWriteReturnsFalse() {
        let evaluator = makeEvaluator(cache: makeCache())
        #expect(!evaluator.isBundleWrite(path: "/usr/bin/git", accessKind: .write))
    }

    @Test("bundle path with read access returns false from isBundleWrite")
    func bundleReadReturnsFalse() {
        let evaluator = makeEvaluator(cache: makeCache())
        #expect(!evaluator.isBundleWrite(path: "/Applications/Foo.app/Contents/MacOS/Foo", accessKind: .read))
    }

    @Test("bundle write path returns true from isBundleWrite")
    func bundleWriteReturnsTrue() {
        let evaluator = makeEvaluator(cache: makeCache())
        #expect(evaluator.isBundleWrite(path: "/Applications/Foo.app/Contents/MacOS/Foo", accessKind: .write))
    }

    // MARK: - evaluate (existing cases)

    @Test("non-bundle path returns nil")
    func nonBundlePathReturnsNil() {
        let evaluator = makeEvaluator(cache: makeCache())
        #expect(evaluator.evaluate(
            accessPath: "/usr/bin/git",
            processTeamID: "T", processSigningID: "s",
            processUID: 501, accessKind: .write,
            ancestors: []
        ) == nil)
    }

    @Test("bundle root rename by wrong team is denied")
    func bundleRootRenameByWrongTeamDenied() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app",
            processTeamID: "WRONGTEAM", processSigningID: "evil.process",
            processUID: 501, accessKind: .write,
            ancestors: []
        )
        #expect(decision?.isAllowed == false)
    }

    @Test("read access to bundle returns nil")
    func readAccessReturnsNil() {
        let evaluator = makeEvaluator(cache: makeCache())
        #expect(evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "TEAM123", processSigningID: "com.example.app",
            processUID: 501, accessKind: .read,
            ancestors: []
        ) == nil)
    }

    @Test("unsigned bundle (cache returns nil) returns nil")
    func unsignedBundleReturnsNil() {
        let cache = BundleCodesignCache(
            ttl: 60,
            executableEnumerator: { _ in [] },
            signatureReader: { _ in nil }
        )
        let evaluator = makeEvaluator(cache: cache)
        #expect(evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "ANYTEAM", processSigningID: "any.signing.id",
            processUID: 501, accessKind: .write,
            ancestors: []
        ) == nil)
    }

    @Test("team ID mismatch returns denied")
    func teamIDMismatchReturnsDenied() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "WRONGTEAM", processSigningID: "com.example.app",
            processUID: 501, accessKind: .write,
            ancestors: []
        )
        #expect(decision?.isAllowed == false)
    }

    @Test("same team ID with any signing ID returns allowed (team-level trust)")
    func sameTeamAnySigningIDReturnsAllowed() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "TEAM123", processSigningID: "com.example.updater",
            processUID: 501, accessKind: .write,
            ancestors: []
        )
        #expect(decision?.isAllowed == true)
    }

    @Test("team ID match returns allowed with bundle self-signer criterion")
    func selfSignerReturnsAllowed() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "TEAM123", processSigningID: "com.example.app",
            processUID: 501, accessKind: .write,
            ancestors: []
        )
        if case .allowed(_, _, _, let criterion) = decision {
            #expect(criterion == "bundle self-signer")
        } else {
            Issue.record("Expected .allowed, got \(String(describing: decision))")
        }
    }

    @Test("external updater exact match returns allowed with external updater criterion")
    func externalUpdaterReturnsAllowed() {
        let updater = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle")
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"), updaters: [updater])
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "SPARKLE", processSigningID: "org.sparkle-project.Sparkle",
            processUID: 501, accessKind: .write,
            ancestors: []
        )
        if case .allowed(_, _, _, let criterion) = decision {
            #expect(criterion == "external updater")
        } else {
            Issue.record("Expected .allowed, got \(String(describing: decision))")
        }
    }

    @Test("external updater team ID match but wrong signing ID returns denied")
    func externalUpdaterWrongSigningIDReturnsDenied() {
        let updater = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle")
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"), updaters: [updater])
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "SPARKLE", processSigningID: "org.sparkle-project.OtherTool",
            processUID: 501, accessKind: .write,
            ancestors: []
        )
        #expect(decision?.isAllowed == false)
    }

    // MARK: - system file helper

    @Test("DesktopServicesHelper as platform binary running as root returns allowed with system file helper criterion")
    func desktopServicesHelperRootAllowed() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: appleTeamID, processSigningID: "com.apple.DesktopServicesHelper",
            processUID: 0, accessKind: .write,
            ancestors: []
        )
        if case .allowed(_, _, _, let criterion) = decision {
            #expect(criterion == "system file helper")
        } else {
            Issue.record("Expected .allowed, got \(String(describing: decision))")
        }
    }

    @Test("DesktopServicesHelper as platform binary running as non-root is denied")
    func desktopServicesHelperNonRootDenied() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: appleTeamID, processSigningID: "com.apple.DesktopServicesHelper",
            processUID: 501, accessKind: .write,
            ancestors: []
        )
        #expect(decision?.isAllowed == false)
    }

    @Test("DesktopServicesHelper with non-platform teamID is denied even as root")
    func desktopServicesHelperSpoofedTeamIDDenied() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "FAKETEAM", processSigningID: "com.apple.DesktopServicesHelper",
            processUID: 0, accessKind: .write,
            ancestors: []
        )
        #expect(decision?.isAllowed == false)
    }

    // MARK: - wildcard direct match

    @Test("wildcard updater matches any signing ID from that team as direct process")
    func wildcardUpdaterDirectMatchAllowed() {
        let updater = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "*")
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"), updaters: [updater])
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "SPARKLE", processSigningID: "org.sparkle-project.Downloader",
            processUID: 501, accessKind: .write,
            ancestors: []
        )
        if case .allowed(_, _, _, let criterion) = decision {
            #expect(criterion == "external updater")
        } else {
            Issue.record("Expected .allowed, got \(String(describing: decision))")
        }
    }

    // MARK: - ancestry: registered updater in tree

    @Test("subprocess of registered updater is allowed via ancestor updater criterion")
    func ancestorUpdaterAllowed() {
        let updater = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle")
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"), updaters: [updater])
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "UNSIGNED", processSigningID: "rsync",
            processUID: 501, accessKind: .write,
            ancestors: [ancestor(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle")]
        )
        if case .allowed(_, _, _, let criterion) = decision {
            #expect(criterion == "ancestor updater")
        } else {
            Issue.record("Expected .allowed, got \(String(describing: decision))")
        }
    }

    @Test("subprocess of wildcard updater is allowed via ancestor updater criterion")
    func ancestorWildcardUpdaterAllowed() {
        let updater = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "*")
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"), updaters: [updater])
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "UNSIGNED", processSigningID: "rsync",
            processUID: 501, accessKind: .write,
            ancestors: [ancestor(teamID: "SPARKLE", signingID: "org.sparkle-project.Installer")]
        )
        if case .allowed(_, _, _, let criterion) = decision {
            #expect(criterion == "ancestor updater")
        } else {
            Issue.record("Expected .allowed, got \(String(describing: decision))")
        }
    }

    @Test("subprocess of updater with wrong ancestor signing ID is denied")
    func ancestorUpdaterWrongSigningIDDenied() {
        let updater = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle")
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"), updaters: [updater])
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "UNSIGNED", processSigningID: "rsync",
            processUID: 501, accessKind: .write,
            ancestors: [ancestor(teamID: "SPARKLE", signingID: "org.sparkle-project.OtherTool")]
        )
        #expect(decision?.isAllowed == false)
    }

    // MARK: - ancestry: bundle self-signer in tree

    @Test("subprocess spawned by bundle self-signer is allowed via ancestor self-signer criterion")
    func ancestorSelfSignerAllowed() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "UNSIGNED", processSigningID: "rsync",
            processUID: 501, accessKind: .write,
            ancestors: [ancestor(teamID: "TEAM123", signingID: "com.example.app")]
        )
        if case .allowed(_, _, _, let criterion) = decision {
            #expect(criterion == "ancestor self-signer")
        } else {
            Issue.record("Expected .allowed, got \(String(describing: decision))")
        }
    }

    @Test("subprocess with unrelated ancestry is denied")
    func unrelatedAncestryDenied() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "UNSIGNED", processSigningID: "rsync",
            processUID: 501, accessKind: .write,
            ancestors: [ancestor(teamID: "EVIL", signingID: "evil.process")]
        )
        #expect(decision?.isAllowed == false)
    }

    @Test("ancestor self-signer in deep tree is allowed")
    func deepAncestorSelfSignerAllowed() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "UNSIGNED", processSigningID: "rsync",
            processUID: 501, accessKind: .write,
            ancestors: [
                ancestor(teamID: "UNRELATED", signingID: "some.shell"),
                ancestor(teamID: "TEAM123", signingID: "com.example.app"),
                ancestor(teamID: "SYSTEM", signingID: "com.apple.launchd")
            ]
        )
        if case .allowed(_, _, _, let criterion) = decision {
            #expect(criterion == "ancestor self-signer")
        } else {
            Issue.record("Expected .allowed, got \(String(describing: decision))")
        }
    }
}
```

- [ ] **Step 2: Run to verify it fails to compile**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/BundleProtectionEvaluatorTests 2>&1 | grep -E "error:|FAILED|passed|failed" | head -10
```

Expected: compile error — `extra argument 'ancestors' in call` (the existing `evaluate()` doesn't have that parameter yet)

- [ ] **Step 3: Update `BundleProtectionEvaluator.evaluate()`**

Replace the full contents of `opfilter/Filter/BundleProtectionEvaluator.swift`:

```swift
//
//  BundleProtectionEvaluator.swift
//  opfilter
//

import Foundation

final class BundleProtectionEvaluator: @unchecked Sendable {
    // Stable sentinel used as ruleID for all bundle-protection decisions.
    // Generated once with `uuidgen` and must never change.
    static let sentinelRuleID = UUID(uuidString: "7358F9B3-7037-4421-90C5-B136AAC9C2E5")!

    private let cache: BundleCodesignCache
    private let updaterSignaturesProvider: @Sendable () -> [BundleUpdaterSignature]

    init(
        cache: BundleCodesignCache,
        updaterSignaturesProvider: @escaping @Sendable () -> [BundleUpdaterSignature]
    ) {
        self.cache = cache
        self.updaterSignaturesProvider = updaterSignaturesProvider
    }

    /// Hot-path gate: returns true when the event should be forced to the slow path.
    func isBundleWrite(path: String, accessKind: AccessKind) -> Bool {
        accessKind == .write && BundlePath.extract(from: path) != nil
    }

    /// Slow-path evaluation. Returns nil → not a bundle write or bundle is unsigned → fall through.
    func evaluate(
        accessPath: String,
        processTeamID: String,
        processSigningID: String,
        processUID: uid_t,
        accessKind: AccessKind,
        ancestors: [AncestorInfo]
    ) -> PolicyDecision? {
        guard let bundlePath = BundlePath.extract(from: accessPath) else { return nil }
        guard accessKind == .write else { return nil }
        guard let bundleSignatures = cache.signatures(forBundlePath: bundlePath) else { return nil }

        let updaters = updaterSignaturesProvider()

        if updaters.contains(where: { $0.matches(teamID: processTeamID, signingID: processSigningID) }) {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "external updater"
            )
        }

        if ancestors.contains(where: { ancestor in updaters.contains(where: { $0.matches(teamID: ancestor.teamID, signingID: ancestor.signingID) }) }) {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "ancestor updater"
            )
        }

        if processTeamID == appleTeamID && processSigningID == "com.apple.DesktopServicesHelper" && processUID == 0 {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "system file helper"
            )
        }

        if processTeamID == bundleSignatures.teamID {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "bundle self-signer"
            )
        }

        if ancestors.contains(where: { $0.teamID == bundleSignatures.teamID }) {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "ancestor self-signer"
            )
        }

        return .denied(
            ruleID: BundleProtectionEvaluator.sentinelRuleID,
            ruleName: bundlePath,
            ruleSource: .builtin,
            allowedCriteria: "bundle signing identity \(bundleSignatures.teamID)"
        )
    }
}
```

- [ ] **Step 4: Run all evaluator tests to verify they pass**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' -only-testing:clearancekitTests/BundleProtectionEvaluatorTests 2>&1 | grep -E "error:|FAILED|passed|failed"
```

Expected: `Test Suite 'BundleProtectionEvaluatorTests' passed`

- [ ] **Step 5: Run full test suite to check no regressions**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | grep -E "error:|FAILED|passed|failed" | tail -5
```

Expected: no failures

- [ ] **Step 6: Commit**

```bash
git add opfilter/Filter/BundleProtectionEvaluator.swift Tests/BundleProtectionEvaluatorTests.swift
git commit -m "feat: add ancestry trust checks to BundleProtectionEvaluator"
```

---

### Task 3: Wire `ancestors` into `evaluate()` call in `FileAuthPipeline`

**Files:**
- Modify: `opfilter/Filter/FileAuthPipeline.swift:236-247`

- [ ] **Step 1: Update the `evaluate()` call in `processSlowPath`**

In `opfilter/Filter/FileAuthPipeline.swift`, find the block at lines 236–247:

```swift
        if let evaluator = bundleProtectionEvaluator,
           let decision = evaluator.evaluate(
               accessPath: event.path,
               processTeamID: event.teamID,
               processSigningID: event.signingID,
               processUID: event.uid,
               accessKind: event.accessKind
           ) {
```

Replace with:

```swift
        if let evaluator = bundleProtectionEvaluator,
           let decision = evaluator.evaluate(
               accessPath: event.path,
               processTeamID: event.teamID,
               processSigningID: event.signingID,
               processUID: event.uid,
               accessKind: event.accessKind,
               ancestors: ancestors
           ) {
```

- [ ] **Step 2: Run full test suite**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | grep -E "error:|FAILED|passed|failed" | tail -5
```

Expected: no failures

- [ ] **Step 3: Commit**

```bash
git add opfilter/Filter/FileAuthPipeline.swift
git commit -m "feat: pass ancestors to BundleProtectionEvaluator in slow path"
```
