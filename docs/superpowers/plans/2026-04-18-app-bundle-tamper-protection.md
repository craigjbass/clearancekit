# App Bundle Tamper Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent malicious processes from writing to `.app` bundle contents by enforcing that only the bundle's own signed processes (or user-approved external updaters) may write inside `/Applications/*.app/` and `~/Applications/*.app/`.

**Architecture:** Adapter-layer pre-evaluation in `opfilter/Filter/`. Three new files (`BundlePath`, `BundleCodesignCache`, `BundleProtectionEvaluator`) intercept bundle writes before `checkFAAPolicy`. Domain types are untouched. A new `bundle_updater_signatures` SQLite table (migration 008, EC-P256 signed) stores approved external updaters. The GUI exposes a `BundleUpdaterAllowlistView`.

**Tech Stack:** Swift, Security.framework (`SecStaticCodeCreateWithPath`, `SecCodeCopySigningInformation`), SQLite, NSXPCConnection, SwiftUI.

---

## File Map

**New — opfilter:**
- `opfilter/Filter/BundlePath.swift` — pure path extraction
- `opfilter/Filter/BundleCodesignCache.swift` — TTL cache of bundle signing identities
- `opfilter/Filter/BundleProtectionEvaluator.swift` — decision logic

**New — Shared:**
- `Shared/BundleUpdaterSignature.swift` — domain type (Codable, Sendable)

**New — Tests:**
- `Tests/BundlePathTests.swift`
- `Tests/BundleCodesignCacheTests.swift`
- `Tests/BundleProtectionEvaluatorTests.swift`
- `Tests/CanonicalBundleUpdaterEncodingTests.swift`

**New — GUI:**
- `clearancekit/Configure/BundleUpdaters/BundleUpdaterStore.swift`
- `clearancekit/Configure/BundleUpdaters/BundleUpdaterAllowlistView.swift`

**Modified:**
- `opfilter/Filter/FileAuthPipeline.swift` — bundle write → slow path; slow path pre-check
- `opfilter/Database/DatabaseMigrations.swift` — migration 008
- `opfilter/Database/Database.swift` — load/save bundle updater signatures; `tableHasRows`
- `opfilter/Policy/PolicyRepository.swift` — load + accessor + mutation + encoded view; `PolicyDatabaseProtocol`
- `Shared/XPCProtocol.swift` — new XPC messages
- `opfilter/XPC/XPCServer.swift` — `ConnectionHandler` + `pushPolicySnapshot`
- `clearancekit/App/XPCClient.swift` — `ClientProtocol` conformance + service mutation
- `clearancekit/Configure/PolicyServiceProtocol.swift` — add `saveBundleUpdaterSignatures`
- `clearancekit/App/ContentView.swift` — sidebar entry

---

## Task 1: BundlePath

**Files:**
- Create: `opfilter/Filter/BundlePath.swift`
- Create: `Tests/BundlePathTests.swift`

- [ ] **Step 1: Write the failing tests**

Create `Tests/BundlePathTests.swift`:

```swift
//
//  BundlePathTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("BundlePath")
struct BundlePathTests {
    @Test("/Applications subpath returns bundle root")
    func applicationsSubpath() {
        #expect(
            BundlePath.extract(from: "/Applications/Foo.app/Contents/MacOS/Foo")
            == "/Applications/Foo.app"
        )
    }

    @Test("~/Applications subpath returns expanded home bundle root")
    func homeApplicationsSubpath() {
        let home = NSHomeDirectory()
        #expect(
            BundlePath.extract(from: home + "/Applications/Bar.app/Contents/Resources/icon.png")
            == home + "/Applications/Bar.app"
        )
    }

    @Test("/usr/bin path returns nil")
    func nonBundlePath() {
        #expect(BundlePath.extract(from: "/usr/bin/git") == nil)
    }

    @Test("path that is the bundle root returns itself")
    func bundleRootPath() {
        #expect(
            BundlePath.extract(from: "/Applications/Foo.app")
            == "/Applications/Foo.app"
        )
    }

    @Test("nested .app returns outer .app")
    func nestedApp() {
        #expect(
            BundlePath.extract(from: "/Applications/Foo.app/Contents/PlugIns/Bar.app/Contents/MacOS/Bar")
            == "/Applications/Foo.app"
        )
    }

    @Test("path with no .app component returns nil")
    func noAppComponent() {
        #expect(BundlePath.extract(from: "/Applications/SomeFile.txt") == nil)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' \
  -only-testing:clearancekitTests/BundlePathTests 2>&1 | tail -20
```

Expected: compile error — `BundlePath` not found.

- [ ] **Step 3: Create BundlePath**

Create `opfilter/Filter/BundlePath.swift`:

```swift
//
//  BundlePath.swift
//  opfilter
//

import Foundation

enum BundlePath {
    static let protectedPrefixes: [String] = [
        "/Applications/",
        NSHomeDirectory() + "/Applications/"
    ]

    /// Returns the enclosing .app path, or nil if not under a protected bundle prefix.
    static func extract(from accessPath: String) -> String? {
        for prefix in protectedPrefixes {
            guard accessPath.hasPrefix(prefix) else { continue }
            let remainder = String(accessPath.dropFirst(prefix.count))
            for component in remainder.split(separator: "/", omittingEmptySubsequences: true) {
                if component.hasSuffix(".app") {
                    return prefix + component
                }
                break
            }
        }
        return nil
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' \
  -only-testing:clearancekitTests/BundlePathTests 2>&1 | tail -20
```

Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add opfilter/Filter/BundlePath.swift Tests/BundlePathTests.swift
git commit -m "feat: add BundlePath pure path extraction with tests"
```

---

## Task 2: BundleCodesignCache

**Files:**
- Create: `opfilter/Filter/BundleCodesignCache.swift`
- Create: `Tests/BundleCodesignCacheTests.swift`

The cache uses two injectable seams: `executableEnumerator` (bundle path → [executable paths]) and `signatureReader` (executable path → (teamID, signingID)?). Both default to real implementations. Tests override both to avoid filesystem and Security.framework access.

- [ ] **Step 1: Write the failing tests**

Create `Tests/BundleCodesignCacheTests.swift`:

```swift
//
//  BundleCodesignCacheTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("BundleCodesignCache")
struct BundleCodesignCacheTests {

    private func makeCache(
        ttl: TimeInterval = 60,
        executables: [String] = ["/fake/App.app/Contents/MacOS/App"],
        reader: @escaping (String) -> (teamID: String, signingID: String)? = { _ in
            (teamID: "TEAM123", signingID: "com.example.app")
        }
    ) -> BundleCodesignCache {
        BundleCodesignCache(
            ttl: ttl,
            executableEnumerator: { _ in executables },
            signatureReader: reader
        )
    }

    @Test("cache miss reads from reader")
    func cacheMissReadsFromReader() {
        var callCount = 0
        let cache = makeCache(reader: { _ in
            callCount += 1
            return (teamID: "TEAM123", signingID: "com.example.app")
        })
        let result = cache.signatures(forBundlePath: "/fake/App.app")
        #expect(result?.teamID == "TEAM123")
        #expect(result?.signingIDs.contains("com.example.app") == true)
        #expect(callCount == 1)
    }

    @Test("second call within TTL uses cache (reader not called again)")
    func cacheHitSkipsReader() {
        var callCount = 0
        let cache = makeCache(reader: { _ in
            callCount += 1
            return (teamID: "TEAM123", signingID: "com.example.app")
        })
        _ = cache.signatures(forBundlePath: "/fake/App.app")
        _ = cache.signatures(forBundlePath: "/fake/App.app")
        #expect(callCount == 1)
    }

    @Test("call after TTL expiry re-reads")
    func ttlExpiryTriggersReRead() {
        var callCount = 0
        let cache = makeCache(ttl: 0.01, reader: { _ in
            callCount += 1
            return (teamID: "TEAM123", signingID: "com.example.app")
        })
        _ = cache.signatures(forBundlePath: "/fake/App.app")
        Thread.sleep(forTimeInterval: 0.05)
        _ = cache.signatures(forBundlePath: "/fake/App.app")
        #expect(callCount == 2)
    }

    @Test("invalidate forces re-read on next call")
    func invalidateForcesReRead() {
        var callCount = 0
        let cache = makeCache(reader: { _ in
            callCount += 1
            return (teamID: "TEAM123", signingID: "com.example.app")
        })
        _ = cache.signatures(forBundlePath: "/fake/App.app")
        cache.invalidate(bundlePath: "/fake/App.app")
        _ = cache.signatures(forBundlePath: "/fake/App.app")
        #expect(callCount == 2)
    }

    @Test("unsigned bundle (reader returns nil for all executables) returns nil")
    func unsignedBundleReturnsNil() {
        let cache = makeCache(reader: { _ in nil })
        #expect(cache.signatures(forBundlePath: "/fake/App.app") == nil)
    }

    @Test("multiple executables with same team ID collect all signing IDs")
    func multipleExecutablesCollectSigningIDs() {
        let cache = BundleCodesignCache(
            ttl: 60,
            executableEnumerator: { _ in [
                "/fake/App.app/Contents/MacOS/App",
                "/fake/App.app/Contents/XPCServices/Helper.xpc/Contents/MacOS/Helper"
            ]},
            signatureReader: { path in
                if path.hasSuffix("/App") { return (teamID: "TEAM123", signingID: "com.example.app") }
                if path.hasSuffix("/Helper") { return (teamID: "TEAM123", signingID: "com.example.helper") }
                return nil
            }
        )
        let result = cache.signatures(forBundlePath: "/fake/App.app")
        #expect(result?.teamID == "TEAM123")
        #expect(result?.signingIDs == ["com.example.app", "com.example.helper"])
    }

    @Test("executables with mixed team IDs: only primary team ID signing IDs included")
    func mixedTeamIDsUsesPrimaryOnly() {
        let cache = BundleCodesignCache(
            ttl: 60,
            executableEnumerator: { _ in [
                "/fake/App.app/Contents/MacOS/App",
                "/fake/App.app/Contents/MacOS/Other"
            ]},
            signatureReader: { path in
                if path.hasSuffix("/App") { return (teamID: "TEAM123", signingID: "com.example.app") }
                if path.hasSuffix("/Other") { return (teamID: "DIFFERENT", signingID: "com.other.thing") }
                return nil
            }
        )
        let result = cache.signatures(forBundlePath: "/fake/App.app")
        #expect(result?.teamID == "TEAM123")
        #expect(result?.signingIDs == ["com.example.app"])
        #expect(result?.signingIDs.contains("com.other.thing") == false)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' \
  -only-testing:clearancekitTests/BundleCodesignCacheTests 2>&1 | tail -20
```

Expected: compile error — `BundleCodesignCache` not found.

- [ ] **Step 3: Create BundleCodesignCache**

Create `opfilter/Filter/BundleCodesignCache.swift`:

```swift
//
//  BundleCodesignCache.swift
//  opfilter
//

import Foundation
import Security
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "bundle-codesign-cache")

// MARK: - BundleSignatures

struct BundleSignatures {
    let teamID: String
    let signingIDs: Set<String>
    let expiry: Date
}

// MARK: - BundleCodesignCache

final class BundleCodesignCache: @unchecked Sendable {
    private let ttl: TimeInterval
    private let executableEnumerator: (String) -> [String]
    private let signatureReader: (String) -> (teamID: String, signingID: String)?
    private let storage: OSAllocatedUnfairLock<[String: BundleSignatures]>

    init(
        ttl: TimeInterval = 60,
        executableEnumerator: @escaping (String) -> [String] = BundleCodesignCache.enumerateExecutables(in:),
        signatureReader: @escaping (String) -> (teamID: String, signingID: String)? = BundleCodesignCache.readSignature(at:)
    ) {
        self.ttl = ttl
        self.executableEnumerator = executableEnumerator
        self.signatureReader = signatureReader
        self.storage = OSAllocatedUnfairLock(initialState: [:])
    }

    /// Returns nil if bundle is unsigned (no signed executables found).
    func signatures(forBundlePath bundlePath: String) -> BundleSignatures? {
        let now = Date()
        if let cached = storage.withLock({ $0[bundlePath] }), cached.expiry > now {
            return cached
        }
        let fresh = loadSignatures(for: bundlePath, now: now)
        if let fresh {
            storage.withLock { $0[bundlePath] = fresh }
        }
        return fresh
    }

    /// Evicts cached entry so the next call re-reads from disk.
    func invalidate(bundlePath: String) {
        storage.withLock { $0.removeValue(forKey: bundlePath) }
    }

    // MARK: - Private

    private func loadSignatures(for bundlePath: String, now: Date) -> BundleSignatures? {
        let executables = executableEnumerator(bundlePath)
        var primaryTeamID = ""
        var signingIDs: Set<String> = []

        for path in executables {
            guard let sig = signatureReader(path) else { continue }
            if primaryTeamID.isEmpty {
                primaryTeamID = sig.teamID
            }
            if sig.teamID == primaryTeamID {
                signingIDs.insert(sig.signingID)
            }
        }

        guard !primaryTeamID.isEmpty else { return nil }
        return BundleSignatures(teamID: primaryTeamID, signingIDs: signingIDs, expiry: now.addingTimeInterval(ttl))
    }

    // MARK: - Real implementations (defaults)

    static func enumerateExecutables(in bundlePath: String) -> [String] {
        let manager = FileManager.default
        var paths: [String] = []

        func addContents(of dir: String) {
            guard let entries = try? manager.contentsOfDirectory(atPath: dir) else { return }
            paths += entries.map { dir + "/" + $0 }
        }

        func addMacOSContents(of containerPath: String) {
            let macOS = containerPath + "/Contents/MacOS"
            addContents(of: macOS)
        }

        // Contents/MacOS/*
        addMacOSContents(of: bundlePath)

        // Contents/XPCServices/*/Contents/MacOS/*
        let xpcServices = bundlePath + "/Contents/XPCServices"
        if let services = try? manager.contentsOfDirectory(atPath: xpcServices) {
            for service in services {
                addMacOSContents(of: xpcServices + "/" + service)
            }
        }

        // Contents/Helpers/*
        addContents(of: bundlePath + "/Contents/Helpers")

        // Contents/Library/LoginItems/*/Contents/MacOS/*
        let loginItems = bundlePath + "/Contents/Library/LoginItems"
        if let items = try? manager.contentsOfDirectory(atPath: loginItems) {
            for item in items {
                addMacOSContents(of: loginItems + "/" + item)
            }
        }

        return paths
    }

    static func readSignature(at executablePath: String) -> (teamID: String, signingID: String)? {
        var code: SecStaticCode?
        let url = URL(fileURLWithPath: executablePath)
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        guard let signingID = dict[kSecCodeInfoIdentifier as String] as? String,
              let teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String else { return nil }
        return (teamID: teamID, signingID: signingID)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' \
  -only-testing:clearancekitTests/BundleCodesignCacheTests 2>&1 | tail -20
```

Expected: all 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add opfilter/Filter/BundleCodesignCache.swift Tests/BundleCodesignCacheTests.swift
git commit -m "feat: add BundleCodesignCache with TTL and seam injection"
```

---

## Task 3: BundleProtectionEvaluator

**Files:**
- Create: `opfilter/Filter/BundleProtectionEvaluator.swift`
- Create: `Tests/BundleProtectionEvaluatorTests.swift`

Sentinel rule UUID for all bundle decisions: `7358F9B3-7037-4421-90C5-B136AAC9C2E5` (generated with `uuidgen`).

- [ ] **Step 1: Write the failing tests**

Create `Tests/BundleProtectionEvaluatorTests.swift`:

```swift
//
//  BundleProtectionEvaluatorTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("BundleProtectionEvaluator")
struct BundleProtectionEvaluatorTests {

    private func makeCache(teamID: String = "TEAM123", signingIDs: Set<String> = ["com.example.app"]) -> BundleCodesignCache {
        BundleCodesignCache(
            ttl: 60,
            executableEnumerator: { _ in ["/fake/App.app/Contents/MacOS/App"] },
            signatureReader: { _ in (teamID: teamID, signingID: signingIDs.first ?? "") }
        )
    }

    private func makeMultiIDCache(teamID: String, signingIDs: Set<String>) -> BundleCodesignCache {
        let idArray = Array(signingIDs)
        var callIndex = 0
        return BundleCodesignCache(
            ttl: 60,
            executableEnumerator: { _ in idArray.map { "/fake/App.app/Contents/MacOS/\($0)" } },
            signatureReader: { path in
                let sigID = idArray.first(where: { path.hasSuffix("/\($0)") }) ?? idArray[0]
                return (teamID: teamID, signingID: sigID)
            }
        )
    }

    private func makeEvaluator(
        cache: BundleCodesignCache,
        updaters: [BundleUpdaterSignature] = []
    ) -> BundleProtectionEvaluator {
        BundleProtectionEvaluator(cache: cache, updaterSignaturesProvider: { updaters })
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

    // MARK: - evaluate

    @Test("non-bundle path returns nil")
    func nonBundlePathReturnsNil() {
        let evaluator = makeEvaluator(cache: makeCache())
        #expect(evaluator.evaluate(accessPath: "/usr/bin/git", processTeamID: "T", processSigningID: "s", accessKind: .write) == nil)
    }

    @Test("read access to bundle returns nil")
    func readAccessReturnsNil() {
        let evaluator = makeEvaluator(cache: makeCache())
        #expect(evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "TEAM123", processSigningID: "com.example.app",
            accessKind: .read
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
            accessKind: .write
        ) == nil)
    }

    @Test("team ID mismatch returns denied")
    func teamIDMismatchReturnsDenied() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123", signingIDs: ["com.example.app"]))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "WRONGTEAM", processSigningID: "com.example.app",
            accessKind: .write
        )
        #expect(decision?.isAllowed == false)
    }

    @Test("team ID match but signing ID not in set returns denied")
    func signingIDNotInSetReturnsDenied() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123", signingIDs: ["com.example.app"]))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "TEAM123", processSigningID: "com.example.other",
            accessKind: .write
        )
        #expect(decision?.isAllowed == false)
    }

    @Test("team ID match and signing ID in set returns allowed with bundle self-signer criterion")
    func selfSignerReturnsAllowed() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123", signingIDs: ["com.example.app"]))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "TEAM123", processSigningID: "com.example.app",
            accessKind: .write
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
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123", signingIDs: ["com.example.app"]), updaters: [updater])
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "SPARKLE", processSigningID: "org.sparkle-project.Sparkle",
            accessKind: .write
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
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123", signingIDs: ["com.example.app"]), updaters: [updater])
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "SPARKLE", processSigningID: "org.sparkle-project.OtherTool",
            accessKind: .write
        )
        #expect(decision?.isAllowed == false)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' \
  -only-testing:clearancekitTests/BundleProtectionEvaluatorTests 2>&1 | tail -20
```

Expected: compile error — `BundleProtectionEvaluator` and `BundleUpdaterSignature` not found.

- [ ] **Step 3: Create BundleUpdaterSignature (needed by evaluator tests)**

Create `Shared/BundleUpdaterSignature.swift`:

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
}
```

- [ ] **Step 4: Create BundleProtectionEvaluator**

Create `opfilter/Filter/BundleProtectionEvaluator.swift`:

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
        accessKind: AccessKind
    ) -> PolicyDecision? {
        guard let bundlePath = BundlePath.extract(from: accessPath) else { return nil }
        guard accessKind == .write else { return nil }
        guard let bundleSignatures = cache.signatures(forBundlePath: bundlePath) else { return nil }

        let updaters = updaterSignaturesProvider()
        if updaters.contains(where: { $0.teamID == processTeamID && $0.signingID == processSigningID }) {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "external updater"
            )
        }

        if processTeamID == bundleSignatures.teamID && bundleSignatures.signingIDs.contains(processSigningID) {
            return .allowed(
                ruleID: BundleProtectionEvaluator.sentinelRuleID,
                ruleName: bundlePath,
                ruleSource: .builtin,
                matchedCriterion: "bundle self-signer"
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

- [ ] **Step 5: Run tests to verify they pass**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' \
  -only-testing:clearancekitTests/BundleProtectionEvaluatorTests 2>&1 | tail -20
```

Expected: all 10 tests pass.

- [ ] **Step 6: Commit**

```bash
git add Shared/BundleUpdaterSignature.swift \
        opfilter/Filter/BundleProtectionEvaluator.swift \
        Tests/BundleProtectionEvaluatorTests.swift
git commit -m "feat: add BundleProtectionEvaluator and BundleUpdaterSignature domain type"
```

---

## Task 4: Pipeline Integration

**Files:**
- Modify: `opfilter/Filter/FileAuthPipeline.swift`
- Modify: `Tests/FileAuthPipelineTests.swift`

`FileAuthPipeline` gains an optional `bundleProtectionEvaluator: BundleProtectionEvaluator?` (default `nil`). Hot path routes bundle writes to slow path. Slow path evaluates before `evaluateAccess`.

- [ ] **Step 1: Write failing pipeline integration tests**

Add to `Tests/FileAuthPipelineTests.swift` (append to the existing file after the last test):

```swift
    // MARK: - Bundle protection integration

    private func makeEvaluator(
        allowed: Bool,
        isBundleWrite: Bool = true
    ) -> BundleProtectionEvaluator {
        let cache = BundleCodesignCache(
            ttl: 60,
            executableEnumerator: { _ in ["/Applications/Foo.app/Contents/MacOS/Foo"] },
            signatureReader: { _ in (teamID: "TEAM", signingID: "com.example") }
        )
        return BundleProtectionEvaluator(
            cache: cache,
            updaterSignaturesProvider: {
                // Return a matching updater so evaluate() returns .allowed when allowed=true
                allowed ? [BundleUpdaterSignature(teamID: "TEAM", signingID: "com.example")] : []
            }
        )
    }

    @Test("bundle write routes to slow path, evaluator decision wins")
    func bundleWriteRoutesToSlowPath() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true
        let evaluator = makeEvaluator(allowed: true)

        let responded = DispatchSemaphore(value: 0)
        var allowedResult = false
        let postRespondCalled = DispatchSemaphore(value: 0)
        var postRespondDecision: PolicyDecision?

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, decision, _, _ in
                postRespondDecision = decision
                postRespondCalled.signal()
            },
            bundleProtectionEvaluator: evaluator
        )
        pipeline.start()

        let event = fileAuthEvent(
            path: "/Applications/Foo.app/Contents/MacOS/Foo",
            accessKind: .write
        ) { allowed, _ in
            allowedResult = allowed
            responded.signal()
        }

        pipeline.submit(event)
        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult == true)
        if case .allowed(_, _, _, let criterion) = postRespondDecision {
            #expect(criterion == "external updater")
        } else {
            Issue.record("Expected .allowed from evaluator, got \(String(describing: postRespondDecision))")
        }
    }

    @Test("bundle write with denied evaluator result: denied")
    func bundleWriteDeniedByEvaluator() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true
        let evaluator = makeEvaluator(allowed: false)

        let responded = DispatchSemaphore(value: 0)
        var allowedResult = true
        let postRespondCalled = DispatchSemaphore(value: 0)

        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, _, _, _ in postRespondCalled.signal() },
            bundleProtectionEvaluator: evaluator
        )
        pipeline.start()

        let event = fileAuthEvent(
            path: "/Applications/Foo.app/Contents/MacOS/Foo",
            accessKind: .write
        ) { allowed, _ in
            allowedResult = allowed
            responded.signal()
        }

        pipeline.submit(event)
        responded.wait()
        postRespondCalled.wait()

        #expect(allowedResult == false)
    }

    @Test("bundle read is NOT routed to slow path by isBundleWrite")
    func bundleReadNotRouted() {
        let processTree = FakePipelineProcessTree()
        processTree.containsResult = true

        let responded = DispatchSemaphore(value: 0)
        let postRespondCalled = DispatchSemaphore(value: 0)
        var postRespondDecision: PolicyDecision?

        let evaluator = makeEvaluator(allowed: true)
        let pipeline = FileAuthPipeline(
            processTree: processTree,
            rulesProvider: { [] },
            allowlistProvider: { [] },
            ancestorAllowlistProvider: { [] },
            postRespond: { _, decision, _, _ in
                postRespondDecision = decision
                postRespondCalled.signal()
            },
            bundleProtectionEvaluator: evaluator
        )
        pipeline.start()

        let event = fileAuthEvent(
            path: "/Applications/Foo.app/Contents/MacOS/Foo",
            accessKind: .read
        ) { _, _ in responded.signal() }

        pipeline.submit(event)
        responded.wait()
        postRespondCalled.wait()

        // Read events fall through to normal policy — noRuleApplies when no rules configured
        if case .noRuleApplies = postRespondDecision {
            // correct
        } else {
            Issue.record("Expected .noRuleApplies for read, got \(String(describing: postRespondDecision))")
        }
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' \
  -only-testing:clearancekitTests/FileAuthPipelineTests 2>&1 | grep -E "FAIL|error:|passed|failed" | tail -20
```

Expected: compile error — `FileAuthPipeline` has no `bundleProtectionEvaluator` parameter.

- [ ] **Step 3: Modify FileAuthPipeline**

In `opfilter/Filter/FileAuthPipeline.swift`:

**Add stored property** after `private let metricsStorage`:
```swift
    private let bundleProtectionEvaluator: BundleProtectionEvaluator?
```

**Add parameter to `init`** (add after `slowSignal: DispatchSemaphore = DispatchSemaphore(value: 0)`):
```swift
        bundleProtectionEvaluator: BundleProtectionEvaluator? = nil,
```

**Assign in init body** (add after `self.metricsStorage = ...`):
```swift
        self.bundleProtectionEvaluator = bundleProtectionEvaluator
```

**Insert in `processHotPath`** after `let rules = rulesProvider()` (line 134) and before `let classification = classifyPaths(...)` (line 135):

```swift
        if let evaluator = bundleProtectionEvaluator,
           evaluator.isBundleWrite(path: event.path, accessKind: event.accessKind) {
            let workItem = SlowWorkItem(
                fileEvent: event,
                rules: rules,
                allowlist: allowlist,
                ancestorAllowlist: ancestorAllowlist
            )
            switch slowQueue.tryEnqueue(workItem) {
            case .enqueued:
                metricsStorage.withLock { $0.slowQueueEnqueueCount += 1 }
                slowSignal.signal()
            case .full:
                metricsStorage.withLock { $0.slowQueueDropCount += 1 }
                logger.warning("SLOW-DROP cid=\(event.correlationID) pid=\(event.processID) path=\(event.path, privacy: .public) ttdMs=\(MachTime.millisecondsToDeadline(event.deadline))")
                event.respond(true, false)
                metricsStorage.withLock { $0.hotPathRespondedCount += 1 }
                let ancestors = processTree.ancestors(of: event.processIdentity)
                postRespondHandler(event, .noRuleApplies, ancestors, 0)
            }
            return
        }
```

**Insert in `processSlowPath`** after `let ancestors = processTree.ancestors(of: event.processIdentity)` (line 207) and before `let decision = evaluateAccess(...)` (line 208):

```swift
        if let evaluator = bundleProtectionEvaluator,
           let decision = evaluator.evaluate(
               accessPath: event.path,
               processTeamID: event.teamID,
               processSigningID: event.signingID,
               accessKind: event.accessKind
           ) {
            event.respond(decision.isAllowed, false)
            postRespondHandler(event, decision, ancestors, dwellNanoseconds)
            return
        }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' \
  -only-testing:clearancekitTests/FileAuthPipelineTests 2>&1 | tail -20
```

Expected: all pipeline tests pass (existing + new).

- [ ] **Step 5: Commit**

```bash
git add opfilter/Filter/FileAuthPipeline.swift Tests/FileAuthPipelineTests.swift
git commit -m "feat: route bundle writes to slow path; evaluator pre-check in slow path"
```

---

## Task 5: Canonical Encoding Tests for BundleUpdaterSignature

**Files:**
- Create: `Tests/CanonicalBundleUpdaterEncodingTests.swift`

Pins the byte-level canonical JSON used for the `bundle_updater_signatures` table signature.

- [ ] **Step 1: Write the tests**

Create `Tests/CanonicalBundleUpdaterEncodingTests.swift`:

```swift
//
//  CanonicalBundleUpdaterEncodingTests.swift
//  clearancekitTests
//
//  Pins the byte-level canonical JSON encoding of [BundleUpdaterSignature] used
//  by Database.saveBundleUpdaterSignatures to compute the EC-P256 table signature.
//  The encoder config here MUST stay in lock-step with Database.canonicalBundleUpdaterSignaturesJSON.
//

import Testing
import Foundation

@Suite("Canonical BundleUpdaterSignature encoding")
struct CanonicalBundleUpdaterEncodingTests {

    private func canonical(_ signatures: [BundleUpdaterSignature]) -> Data {
        let sorted = signatures.sorted { $0.id.uuidString < $1.id.uuidString }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try! encoder.encode(sorted)
    }

    @Test("empty list encodes to []")
    func emptyListEncodesToBrackets() {
        let json = String(data: canonical([]), encoding: .utf8)
        #expect(json == "[]")
    }

    @Test("single entry encodes with sorted keys")
    func singleEntryEncodesSorted() {
        let sig = BundleUpdaterSignature(
            id: UUID(uuidString: "E5D15228-3561-42CC-972C-54C92B88CB6C")!,
            teamID: "SPARKLE01",
            signingID: "org.sparkle-project.Sparkle"
        )
        let json = String(data: canonical([sig]), encoding: .utf8) ?? ""
        // Keys must be in ASCII sort order: id < signingID < teamID
        let idRange = json.range(of: "\"id\"")!
        let sigRange = json.range(of: "\"signingID\"")!
        let teamRange = json.range(of: "\"teamID\"")!
        #expect(idRange.lowerBound < sigRange.lowerBound)
        #expect(sigRange.lowerBound < teamRange.lowerBound)
    }

    @Test("multiple entries are sorted by id.uuidString")
    func multipleEntriesSortedByID() {
        let sig1 = BundleUpdaterSignature(
            id: UUID(uuidString: "E5D15228-3561-42CC-972C-54C92B88CB6C")!,
            teamID: "TEAM_E",
            signingID: "com.e"
        )
        let sig2 = BundleUpdaterSignature(
            id: UUID(uuidString: "1CE13515-838A-45BD-BD4A-A7468D4F6014")!,
            teamID: "TEAM_1",
            signingID: "com.1"
        )
        // sig2 UUID ("1CE...") sorts before sig1 UUID ("E5D...")
        let json = String(data: canonical([sig1, sig2]), encoding: .utf8) ?? ""
        let range1 = json.range(of: "TEAM_1")!
        let rangeE = json.range(of: "TEAM_E")!
        #expect(range1.lowerBound < rangeE.lowerBound)
    }

    @Test("round-trip encode/decode preserves all fields")
    func roundTripPreservesFields() throws {
        let original = BundleUpdaterSignature(
            id: UUID(uuidString: "E5D15228-3561-42CC-972C-54C92B88CB6C")!,
            teamID: "SPARKLE01",
            signingID: "org.sparkle-project.Sparkle"
        )
        let data = canonical([original])
        let decoded = try JSONDecoder().decode([BundleUpdaterSignature].self, from: data)
        #expect(decoded.count == 1)
        #expect(decoded[0].id == original.id)
        #expect(decoded[0].teamID == original.teamID)
        #expect(decoded[0].signingID == original.signingID)
    }
}
```

- [ ] **Step 2: Run tests**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' \
  -only-testing:clearancekitTests/CanonicalBundleUpdaterEncodingTests 2>&1 | tail -20
```

Expected: all 4 tests pass (type already exists from Task 3).

- [ ] **Step 3: Commit**

```bash
git add Tests/CanonicalBundleUpdaterEncodingTests.swift
git commit -m "test: pin canonical JSON encoding for BundleUpdaterSignature"
```

---

## Task 6: Database Migration and Load/Save

**Files:**
- Modify: `opfilter/Database/DatabaseMigrations.swift`
- Modify: `opfilter/Database/Database.swift`
- Modify: `opfilter/Policy/PolicyRepository.swift` (the `PolicyDatabaseProtocol` declaration inside it)

- [ ] **Step 1: Add migration 008**

In `opfilter/Database/DatabaseMigrations.swift`, find `allMigrations`:

```swift
let allMigrations: [Migration] = [
    ...
    Migration(version: 7, name: "Add authorization columns", up: migration007AddAuthorizationColumns),
]
```

Change to:
```swift
let allMigrations: [Migration] = [
    ...
    Migration(version: 7, name: "Add authorization columns", up: migration007AddAuthorizationColumns),
    Migration(version: 8, name: "Add bundle_updater_signatures table", up: migration008AddBundleUpdaterSignatures),
]
```

Then add the function at the end of the file:

```swift
// MARK: - Migration 008: Add bundle_updater_signatures table

private func migration008AddBundleUpdaterSignatures(_ db: Database) {
    db.execute("""
        CREATE TABLE bundle_updater_signatures (
            id TEXT PRIMARY KEY,
            team_id TEXT NOT NULL,
            signing_id TEXT NOT NULL
        )
    """)
    NSLog("Migration 008: Created bundle_updater_signatures table")
}
```

- [ ] **Step 2: Add tableHasRows case, load/save methods, and canonical JSON to Database.swift**

In `opfilter/Database/Database.swift`:

**Update `tableHasRows`** — add the new case:
```swift
    private func tableHasRows(_ table: String) -> Bool {
        switch table {
        case "user_rules":              break
        case "user_allowlist":          break
        case "user_ancestor_allowlist": break
        case "user_jail_rules":         break
        case "feature_flags":           break
        case "bundle_updater_signatures": break
        default: preconditionFailure("Unexpected table name: \(table)")
        }
        var found = false
        query("SELECT 1 FROM \(table) LIMIT 1") { _ in found = true }
        return found
    }
```

**Add new section** before the `// MARK: - Signature verification` comment:

```swift
    // MARK: - Bundle Updater Signatures

    func loadBundleUpdaterSignaturesResult() -> DatabaseLoadResult<BundleUpdaterSignature> {
        var signatures: [BundleUpdaterSignature] = []
        query("SELECT id, team_id, signing_id FROM bundle_updater_signatures ORDER BY rowid") { stmt in
            let uuidString = columnText(stmt, 0)
            guard let id = UUID(uuidString: uuidString) else {
                NSLog("Database: Skipping bundle updater signature row with invalid UUID '%@'", uuidString)
                return
            }
            signatures.append(BundleUpdaterSignature(
                id: id,
                teamID: columnText(stmt, 1),
                signingID: columnText(stmt, 2)
            ))
        }
        switch checkSignature(table: "bundle_updater_signatures", content: canonicalBundleUpdaterSignaturesJSON(signatures)) {
        case .verified, .uninitialized:
            NSLog("Database: Loaded %d bundle updater signature(s)", signatures.count)
            return .ok(signatures)
        case .suspect:
            NSLog("Database: Signature verification failed for bundle_updater_signatures — discarding %d signature(s)", signatures.count)
            return .suspect(signatures)
        }
    }

    func saveBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature]) {
        inTransaction {
            execute("DELETE FROM bundle_updater_signatures")
            for signature in signatures {
                execute("""
                    INSERT INTO bundle_updater_signatures (id, team_id, signing_id)
                    VALUES (?, ?, ?)
                """, bindings: [
                    .text(signature.id.uuidString),
                    .text(signature.teamID),
                    .text(signature.signingID),
                ])
            }
            updateSignature(table: "bundle_updater_signatures", content: canonicalBundleUpdaterSignaturesJSON(signatures))
        }
    }

    private func canonicalBundleUpdaterSignaturesJSON(_ signatures: [BundleUpdaterSignature]) -> Data {
        let sorted = signatures.sorted { $0.id.uuidString < $1.id.uuidString }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let encoded = try? encoder.encode(sorted) else {
            fatalError("Database: Failed to JSON-encode bundle updater signatures — [BundleUpdaterSignature] must always be encodable")
        }
        return encoded
    }
```

- [ ] **Step 3: Update PolicyDatabaseProtocol**

In `opfilter/Policy/PolicyRepository.swift`, the `PolicyDatabaseProtocol` declaration (lines 23–34). Add two methods:

```swift
protocol PolicyDatabaseProtocol: AnyObject {
    func loadUserRulesResult() -> DatabaseLoadResult<FAARule>
    func loadUserAllowlistResult() -> DatabaseLoadResult<AllowlistEntry>
    func loadUserAncestorAllowlistResult() -> DatabaseLoadResult<AncestorAllowlistEntry>
    func loadUserJailRulesResult() -> DatabaseLoadResult<JailRule>
    func loadFeatureFlagsResult() -> DatabaseLoadResult<FeatureFlag>
    func loadBundleUpdaterSignaturesResult() -> DatabaseLoadResult<BundleUpdaterSignature>
    func saveUserRules(_ rules: [FAARule])
    func saveUserAllowlist(_ entries: [AllowlistEntry])
    func saveUserAncestorAllowlist(_ entries: [AncestorAllowlistEntry])
    func saveUserJailRules(_ rules: [JailRule])
    func saveFeatureFlags(_ flags: [FeatureFlag])
    func saveBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature])
}
```

- [ ] **Step 4: Build to verify no compile errors**

```bash
xcodebuild build -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | grep -E "error:|Build succeeded|Build FAILED" | tail -10
```

Expected: `Build succeeded`

- [ ] **Step 5: Commit**

```bash
git add opfilter/Database/DatabaseMigrations.swift \
        opfilter/Database/Database.swift \
        opfilter/Policy/PolicyRepository.swift
git commit -m "feat: add migration 008 and bundle_updater_signatures DB persistence"
```

---

## Task 7: PolicyRepository Changes

**Files:**
- Modify: `opfilter/Policy/PolicyRepository.swift`

- [ ] **Step 1: Add bundleUpdaterSignatures to State**

In `PolicyRepository.swift`, find the `State` struct and add the new field:

```swift
    private struct State {
        var managedRules: [FAARule] = []
        var userRules: [FAARule] = []
        var xprotectEntries: [AllowlistEntry] = []
        var managedAllowlist: [AllowlistEntry] = []
        var userAllowlist: [AllowlistEntry] = []
        var managedAncestorAllowlist: [AncestorAllowlistEntry] = []
        var userAncestorAllowlist: [AncestorAllowlistEntry] = []
        var managedJailRules: [JailRule] = []
        var userJailRules: [JailRule] = []
        var pendingSuspectUserRules: [FAARule]?
        var pendingSuspectUserAllowlist: [AllowlistEntry]?
        var featureFlags: [FeatureFlag] = []
        var mcpEnabled: Bool = false
        var bundleUpdaterSignatures: [BundleUpdaterSignature] = []
    }
```

- [ ] **Step 2: Load in init**

In `PolicyRepository.init`, after the `loadFeatureFlagsResult()` switch block (after line 113), add:

```swift
        switch database.loadBundleUpdaterSignaturesResult() {
        case .ok(let signatures):
            initialState.bundleUpdaterSignatures = signatures
        case .suspect(let signatures):
            logger.warning("PolicyRepository: Signature issue for bundle_updater_signatures — discarding \(signatures.count) suspect signature(s)")
        }
```

- [ ] **Step 3: Add accessor, mutation, and encoded view**

After the `// MARK: - Feature flags` section, add a new section:

```swift
    // MARK: - Bundle updater signatures

    func bundleUpdaterSignatures() -> [BundleUpdaterSignature] {
        storage.withLock { $0.bundleUpdaterSignatures }
    }

    func setBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature]) {
        storage.withLock { $0.bundleUpdaterSignatures = signatures }
        database.saveBundleUpdaterSignatures(signatures)
    }

    func encodedBundleUpdaterSignatures() -> NSData {
        let signatures = storage.withLock { $0.bundleUpdaterSignatures }
        guard let data = try? JSONEncoder().encode(signatures) else {
            fatalError("PolicyRepository: Failed to encode bundle updater signatures — this is a bug")
        }
        return data as NSData
    }
```

- [ ] **Step 4: Build**

```bash
xcodebuild build -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | grep -E "error:|Build succeeded|Build FAILED" | tail -10
```

Expected: `Build succeeded`

- [ ] **Step 5: Commit**

```bash
git add opfilter/Policy/PolicyRepository.swift
git commit -m "feat: load and expose bundle updater signatures in PolicyRepository"
```

---

## Task 8: XPC Protocol Additions

**Files:**
- Modify: `Shared/XPCProtocol.swift`

- [ ] **Step 1: Add to ServiceProtocol**

In `Shared/XPCProtocol.swift`, add to `ServiceProtocol` (before the closing `}`):

```swift
    // Bundle updater signature mutations (GUI → opfilter). Opfilter stores, signs,
    // and pushes the updated list to all GUI clients.
    func saveBundleUpdaterSignatures(_ signaturesData: NSData, withReply reply: @escaping (Bool) -> Void)
```

- [ ] **Step 2: Add to ClientProtocol**

In `Shared/XPCProtocol.swift`, add to `ClientProtocol` (before the closing `}`):

```swift
    // Opfilter pushes the current bundle updater signatures on connect and
    // whenever the list changes.
    func bundleUpdaterSignaturesUpdated(_ signaturesData: NSData)
```

- [ ] **Step 3: Build**

```bash
xcodebuild build -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | grep -E "error:|Build succeeded|Build FAILED" | tail -10
```

Expected: `Build FAILED` — `ConnectionHandler` and `XPCClient` don't yet conform.

- [ ] **Step 4: Commit the protocol change**

```bash
git add Shared/XPCProtocol.swift
git commit -m "feat: add bundle updater signature XPC messages to ServiceProtocol and ClientProtocol"
```

---

## Task 9: XPCServer Changes

**Files:**
- Modify: `opfilter/XPC/XPCServer.swift`

- [ ] **Step 1: Add server-side mutation handler**

In `XPCServer.swift`, in the `// MARK: - Jail rule mutations` section area, add a new section:

```swift
    // MARK: - Bundle updater signature mutations

    fileprivate func applySaveBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature]) {
        guard let context else { return }
        context.policyRepository.setBundleUpdaterSignatures(signatures)
        broadcaster.broadcastToAllClients { $0.bundleUpdaterSignaturesUpdated(context.policyRepository.encodedBundleUpdaterSignatures()) }
    }
```

- [ ] **Step 2: Add to pushPolicySnapshot**

In `pushPolicySnapshot(to:context:)`, add before `proxy.serviceReady(true)`:

```swift
        proxy.bundleUpdaterSignaturesUpdated(context.policyRepository.encodedBundleUpdaterSignatures())
```

- [ ] **Step 3: Add to ConnectionHandler's ServiceProtocol conformance**

In `ConnectionHandler` (the `private final class` at the bottom of `XPCServer.swift`), add:

```swift
    func saveBundleUpdaterSignatures(_ signaturesData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        guard let signatures = try? JSONDecoder().decode([BundleUpdaterSignature].self, from: signaturesData as Data) else {
            reply(false); return
        }
        server.serverQueue.async {
            server.applySaveBundleUpdaterSignatures(signatures)
            reply(true)
        }
    }
```

- [ ] **Step 4: Build (still expect failure — XPCClient missing conformance)**

```bash
xcodebuild build -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | grep -E "error:|Build succeeded|Build FAILED" | tail -10
```

- [ ] **Step 5: Commit**

```bash
git add opfilter/XPC/XPCServer.swift
git commit -m "feat: handle saveBundleUpdaterSignatures in XPCServer and push on connect"
```

---

## Task 10: PolicyServiceProtocol + BundleUpdaterStore + XPCClient Changes

**Files:**
- Modify: `clearancekit/Configure/PolicyServiceProtocol.swift`
- Create: `clearancekit/Configure/BundleUpdaters/BundleUpdaterStore.swift`
- Modify: `clearancekit/App/XPCClient.swift`

`BundleUpdaterStore` must exist before `XPCClient` references it, so all three files are committed together.

- [ ] **Step 1: Add to PolicyServiceProtocol**

In `clearancekit/Configure/PolicyServiceProtocol.swift`, add to the protocol:

```swift
    func saveBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature])
```

- [ ] **Step 2: Create BundleUpdaterStore**

Create `clearancekit/Configure/BundleUpdaters/BundleUpdaterStore.swift`:

```swift
//
//  BundleUpdaterStore.swift
//  clearancekit
//

import Foundation
import Combine

/// View-layer cache of the approved external bundle updater list.
/// opfilter is authoritative; this holds a local copy and forwards mutations.
@MainActor
final class BundleUpdaterStore: ObservableObject {
    static let shared = BundleUpdaterStore(
        service: XPCClient.shared,
        authenticate: { try await BiometricAuth.authenticate(reason: $0) }
    )

    @Published private(set) var signatures: [BundleUpdaterSignature] = []

    private let service: PolicyServiceProtocol
    private let authenticate: Authenticate

    init(service: PolicyServiceProtocol, authenticate: @escaping Authenticate) {
        self.service = service
        self.authenticate = authenticate
    }

    func receivedSignatures(_ signatures: [BundleUpdaterSignature]) {
        self.signatures = signatures
    }

    func add(_ signature: BundleUpdaterSignature) async throws {
        try await authenticate("Add a bundle updater allowlist entry")
        signatures.append(signature)
        service.saveBundleUpdaterSignatures(signatures)
    }

    func remove(_ signature: BundleUpdaterSignature) async throws {
        try await authenticate("Remove a bundle updater allowlist entry")
        signatures.removeAll { $0.id == signature.id }
        service.saveBundleUpdaterSignatures(signatures)
    }
}
```

- [ ] **Step 3: Add service mutation method to XPCClient**

In `XPCClient.swift`, after `setMCPEnabled`:

```swift
    func saveBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature]) {
        guard let data = try? JSONEncoder().encode(signatures) else { return }
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            logger.error("XPCClient: saveBundleUpdaterSignatures error: \(error.localizedDescription, privacy: .public)")
        }) as? ServiceProtocol else { return }
        service.saveBundleUpdaterSignatures(data as NSData) { success in
            if !success { logger.error("XPCClient: saveBundleUpdaterSignatures rejected by service") }
        }
    }
```

- [ ] **Step 4: Add ClientProtocol conformance to XPCClient**

In the `extension XPCClient: ClientProtocol` section, add:

```swift
    nonisolated func bundleUpdaterSignaturesUpdated(_ signaturesData: NSData) {
        guard let signatures = try? JSONDecoder().decode([BundleUpdaterSignature].self, from: signaturesData as Data) else {
            logger.fault("XPCClient: Failed to decode bundle updater signatures — version mismatch, invalidating connection")
            Task { @MainActor in self.handleServiceVersionMismatch() }
            return
        }
        Task { @MainActor in
            BundleUpdaterStore.shared.receivedSignatures(signatures)
        }
    }
```

- [ ] **Step 5: Build**

```bash
xcodebuild build -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | grep -E "error:|Build succeeded|Build FAILED" | tail -10
```

Expected: `Build succeeded`

- [ ] **Step 6: Commit**

```bash
git add clearancekit/Configure/PolicyServiceProtocol.swift \
        clearancekit/Configure/BundleUpdaters/BundleUpdaterStore.swift \
        clearancekit/App/XPCClient.swift
git commit -m "feat: add BundleUpdaterStore and wire bundleUpdaterSignatures through XPC client"
```

---

## Task 11: BundleUpdaterAllowlistView + ContentView

**Files:**
- Create: `clearancekit/Configure/BundleUpdaters/BundleUpdaterAllowlistView.swift`
- Modify: `clearancekit/App/ContentView.swift`

- [ ] **Step 1: Create BundleUpdaterAllowlistView**

Create `clearancekit/Configure/BundleUpdaters/BundleUpdaterAllowlistView.swift`:

```swift
//
//  BundleUpdaterAllowlistView.swift
//  clearancekit
//

import SwiftUI

struct BundleUpdaterAllowlistView: View {
    @StateObject private var store = BundleUpdaterStore.shared
    @State private var isAddingEntry = false
    @State private var authError: Error? = nil

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            entryList
        }
        .navigationTitle("Bundle Updater Allowlist")
        .sheet(isPresented: $isAddingEntry) {
            ProcessPickerView { process in
                let entry = BundleUpdaterSignature(teamID: process.teamID, signingID: process.signingID)
                Task {
                    do {
                        try await store.add(entry)
                        isAddingEntry = false
                    } catch {
                        if !BiometricAuth.isUserCancellation(error) { authError = error }
                    }
                }
            } onCancel: {
                isAddingEntry = false
            }
        }
        .alert("Authentication Failed", isPresented: Binding(
            get: { authError != nil },
            set: { if !$0 { authError = nil } }
        )) {
            Button("OK") { authError = nil }
        } message: {
            if let error = authError { Text(error.localizedDescription) }
        }
    }

    private var toolbar: some View {
        HStack {
            Spacer()
            Button("Add Entry") { isAddingEntry = true }
        }
        .padding()
        .background(Color(NSColor.windowBackgroundColor))
    }

    @ViewBuilder
    private var entryList: some View {
        if store.signatures.isEmpty {
            ContentUnavailableView(
                "No Bundle Updater Entries",
                systemImage: "app.badge.checkmark",
                description: Text("Add external updaters (e.g. Sparkle) that are allowed to write inside .app bundles.")
            )
        } else {
            List {
                ForEach(store.signatures) { entry in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.signingID)
                                .font(.system(.body, design: .monospaced))
                                .lineLimit(1)
                            Text(entry.teamID)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Remove") {
                            Task {
                                do {
                                    try await store.remove(entry)
                                } catch {
                                    if !BiometricAuth.isUserCancellation(error) { authError = error }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 3: Add sidebar entry to ContentView**

In `clearancekit/App/ContentView.swift`:

**Add case to `SidebarItem` enum** (after `case allowlist`):
```swift
    case bundleUpdaters = "Bundle Updaters"
```

**Add icon** to `var icon: String` switch (after the `allowlist` case):
```swift
        case .bundleUpdaters: return "lock.app.dashed.trianglebadge.exclamationmark"
```

**Add to sidebar List** in the `Configure` section (after the `allowlist` label):
```swift
                        Label(SidebarItem.bundleUpdaters.rawValue, systemImage: SidebarItem.bundleUpdaters.icon)
                            .tag(SidebarItem.bundleUpdaters)
```

**Add to detail switch** (after the `allowlist` case):
```swift
                case .bundleUpdaters: BundleUpdaterAllowlistView()
```

- [ ] **Step 4: Build**

```bash
xcodebuild build -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | grep -E "error:|Build succeeded|Build FAILED" | tail -10
```

Expected: `Build succeeded`

- [ ] **Step 5: Run all tests**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | tail -30
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add clearancekit/Configure/BundleUpdaters/BundleUpdaterAllowlistView.swift \
        clearancekit/App/ContentView.swift
git commit -m "feat: add BundleUpdaterAllowlistView and sidebar entry"
```

---

## Task 12: main.swift Wiring

**Files:**
- Modify: `opfilter/main.swift`

Wire `BundleCodesignCache` + `BundleProtectionEvaluator` into the pipeline and add cache invalidation in `postRespond`.

- [ ] **Step 1: Modify main.swift**

In `opfilter/main.swift`, find the `let postRespondHandler` line (around line 51) and add new declarations after it:

```swift
let bundleCodesignCache = BundleCodesignCache()
let bundleProtectionEvaluator = BundleProtectionEvaluator(
    cache: bundleCodesignCache,
    updaterSignaturesProvider: { policyRepository.bundleUpdaterSignatures() }
)
```

Update the `postRespond` closure inside `FileAuthPipeline(...)` to add cache invalidation:

```swift
    postRespond: { event, decision, ancestors, dwell in
        postRespondHandler.postRespond(fileEvent: event, decision: decision, ancestors: ancestors, dwellNanoseconds: dwell)
        if event.accessKind == .write, event.path.contains("/_CodeSignature/"),
           let bundlePath = BundlePath.extract(from: event.path) {
            bundleCodesignCache.invalidate(bundlePath: bundlePath)
        }
    },
```

Add `bundleProtectionEvaluator` to the `FileAuthPipeline` init call (add after the `slowSignal` argument):

```swift
    bundleProtectionEvaluator: bundleProtectionEvaluator,
```

- [ ] **Step 2: Build**

```bash
xcodebuild build -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | grep -E "error:|Build succeeded|Build FAILED" | tail -10
```

Expected: `Build succeeded`

- [ ] **Step 3: Run all tests**

```bash
xcodebuild test -scheme clearancekitTests -destination 'platform=macOS' 2>&1 | tail -30
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add opfilter/main.swift
git commit -m "feat: wire BundleProtectionEvaluator into pipeline with cache invalidation on _CodeSignature writes"
```
