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
