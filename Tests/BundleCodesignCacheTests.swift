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
