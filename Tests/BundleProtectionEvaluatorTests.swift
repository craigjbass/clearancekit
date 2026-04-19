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

    @Test("bundle root itself returns false from isBundleWrite (moving the app, not writing inside it)")
    func bundleRootReturnsFalseFromIsBundleWrite() {
        let evaluator = makeEvaluator(cache: makeCache())
        #expect(!evaluator.isBundleWrite(path: "/Applications/Foo.app", accessKind: .write))
    }

    // MARK: - evaluate

    @Test("non-bundle path returns nil")
    func nonBundlePathReturnsNil() {
        let evaluator = makeEvaluator(cache: makeCache())
        #expect(evaluator.evaluate(accessPath: "/usr/bin/git", processTeamID: "T", processSigningID: "s", accessKind: .write) == nil)
    }

    @Test("bundle root itself returns nil from evaluate (moving the app is not a bundle tamper)")
    func bundleRootReturnsNilFromEvaluate() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        #expect(evaluator.evaluate(
            accessPath: "/Applications/Foo.app",
            processTeamID: "WRONGTEAM", processSigningID: "evil.process",
            accessKind: .write
        ) == nil)
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
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "WRONGTEAM", processSigningID: "com.example.app",
            accessKind: .write
        )
        #expect(decision?.isAllowed == false)
    }

    @Test("same team ID with any signing ID returns allowed (team-level trust)")
    func sameTeamAnySigningIDReturnsAllowed() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "TEAM123", processSigningID: "com.example.updater",
            accessKind: .write
        )
        #expect(decision?.isAllowed == true)
    }

    @Test("team ID match returns allowed with bundle self-signer criterion")
    func selfSignerReturnsAllowed() {
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"))
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
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"), updaters: [updater])
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
        let evaluator = makeEvaluator(cache: makeCache(teamID: "TEAM123"), updaters: [updater])
        let decision = evaluator.evaluate(
            accessPath: "/Applications/Foo.app/Contents/MacOS/Foo",
            processTeamID: "SPARKLE", processSigningID: "org.sparkle-project.OtherTool",
            accessKind: .write
        )
        #expect(decision?.isAllowed == false)
    }
}
