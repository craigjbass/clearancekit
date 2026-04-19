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
    let expiry: Date
}

// MARK: - BundleCodesignCache

final class BundleCodesignCache: @unchecked Sendable {
    private let ttl: TimeInterval
    private let executableEnumerator: (String) -> [String]
    private let signatureReader: (String) -> String?
    private let storage: OSAllocatedUnfairLock<[String: BundleSignatures]>

    init(
        ttl: TimeInterval = 60,
        executableEnumerator: @escaping (String) -> [String] = BundleCodesignCache.enumerateExecutables(in:),
        signatureReader: @escaping (String) -> String? = BundleCodesignCache.readTeamID(at:)
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
        for path in executableEnumerator(bundlePath) {
            if let teamID = signatureReader(path) {
                return BundleSignatures(teamID: teamID, expiry: now.addingTimeInterval(ttl))
            }
        }
        return nil
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
            addContents(of: containerPath + "/Contents/MacOS")
        }

        addMacOSContents(of: bundlePath)

        let xpcServices = bundlePath + "/Contents/XPCServices"
        if let services = try? manager.contentsOfDirectory(atPath: xpcServices) {
            for service in services {
                addMacOSContents(of: xpcServices + "/" + service)
            }
        }

        addContents(of: bundlePath + "/Contents/Helpers")

        let loginItems = bundlePath + "/Contents/Library/LoginItems"
        if let items = try? manager.contentsOfDirectory(atPath: loginItems) {
            for item in items {
                addMacOSContents(of: loginItems + "/" + item)
            }
        }

        return paths
    }

    static func readTeamID(at executablePath: String) -> String? {
        var code: SecStaticCode?
        let url = URL(fileURLWithPath: executablePath)
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }
}
