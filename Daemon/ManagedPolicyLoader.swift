//
//  ManagedPolicyLoader.swift
//  clearancekit-daemon
//
//  Reads the managed FAAPolicy preference delivered via MDM or a manually
//  installed .mobileconfig profile. Uses CFPreferencesCopyAppValue which
//  reads the merged preferences layer including managed profiles. This is
//  safe because the daemon runs as root — all writable preference locations
//  (/var/root/Library/Preferences, /Library/Preferences,
//  /Library/Managed Preferences) are root-owned, so no unprivileged user
//  can shadow the managed value.
//
//  Plist / mobileconfig schema — entry in the FAAPolicy array:
//
//    ID                          (string, optional)  — stable UUID string;
//                                                       omit to auto-derive
//                                                       from ProtectedPathPrefix
//    ProtectedPathPrefix         (string, required)  — path or glob pattern
//    AllowedProcessPaths         (array of strings)
//    AllowedTeamIDs              (array of strings)
//    AllowedSigningIDs           (array of strings)
//    AllowedAncestorProcessPaths (array of strings)
//    AllowedAncestorTeamIDs      (array of strings)
//    AllowedAncestorSigningIDs   (array of strings)
//

import Foundation
import CommonCrypto

enum ManagedPolicyLoader {
    private static let preferencesDomain: CFString = XPCConstants.bundleIDPrefix as CFString
    private static let policyKey: CFString          = "FAAPolicy" as CFString

    /// UUID v5 namespace used when deriving stable rule IDs from a path string.
    /// This is the RFC 4122 URL namespace: 6ba7b811-9dad-11d1-80b4-00c04fd430c8
    private static let uuidV5Namespace = UUID(uuidString: "6BA7B811-9DAD-11D1-80B4-00C04FD430C8")!

    /// Reads the managed FAAPolicy from CFPreferences.
    /// Call `loadWithSync()` when you want to guarantee the cache is flushed first
    /// (e.g. on a user-triggered resync).
    static func load() -> [FAARule] {
        guard let raw = CFPreferencesCopyAppValue(policyKey, preferencesDomain) as? [[String: Any]] else {
            NSLog("ManagedPolicyLoader: No managed FAAPolicy found — running without managed tier")
            return []
        }
        let rules = raw.compactMap(parseRule)
        NSLog("ManagedPolicyLoader: Loaded %d managed rule(s)", rules.count)
        return rules
    }

    /// Flushes the CFPreferences cache before reading so that a freshly
    /// delivered MDM payload is picked up without a daemon restart.
    static func loadWithSync() -> [FAARule] {
        CFPreferencesAppSynchronize(preferencesDomain)
        return load()
    }

    // MARK: - Private

    private static func parseRule(_ dict: [String: Any]) -> FAARule? {
        guard let path = dict["ProtectedPathPrefix"] as? String, !path.isEmpty else {
            NSLog("ManagedPolicyLoader: Skipping rule with missing or empty ProtectedPathPrefix")
            return nil
        }

        let id: UUID
        if let idString = dict["ID"] as? String, let parsed = UUID(uuidString: idString) {
            id = parsed
        } else {
            id = deterministicID(forPath: path)
        }

        return FAARule(
            id: id,
            protectedPathPrefix: path,
            allowedProcessPaths:         dict["AllowedProcessPaths"]         as? [String] ?? [],
            allowedTeamIDs:              dict["AllowedTeamIDs"]              as? [String] ?? [],
            allowedSigningIDs:           dict["AllowedSigningIDs"]           as? [String] ?? [],
            allowedAncestorProcessPaths: dict["AllowedAncestorProcessPaths"] as? [String] ?? [],
            allowedAncestorTeamIDs:      dict["AllowedAncestorTeamIDs"]      as? [String] ?? [],
            allowedAncestorSigningIDs:   dict["AllowedAncestorSigningIDs"]   as? [String] ?? []
        )
    }

    /// Derives a stable UUID v5 (RFC 4122, SHA-1) for a rule when no explicit
    /// ID is provided. The name is the UTF-8 encoding of the ProtectedPathPrefix.
    private static func deterministicID(forPath path: String) -> UUID {
        var nsBytes = uuidV5Namespace.uuid
        let nameBytes = Array(path.utf8)

        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        var ctx = CC_SHA1_CTX()
        CC_SHA1_Init(&ctx)
        withUnsafeBytes(of: &nsBytes) { ptr in
            _ = CC_SHA1_Update(&ctx, ptr.baseAddress, CC_LONG(ptr.count))
        }
        CC_SHA1_Update(&ctx, nameBytes, CC_LONG(nameBytes.count))
        CC_SHA1_Final(&digest, &ctx)

        // Set version = 5 and RFC 4122 variant bits.
        digest[6] = (digest[6] & 0x0F) | 0x50
        digest[8] = (digest[8] & 0x3F) | 0x80

        return UUID(uuid: (
            digest[0],  digest[1],  digest[2],  digest[3],
            digest[4],  digest[5],  digest[6],  digest[7],
            digest[8],  digest[9],  digest[10], digest[11],
            digest[12], digest[13], digest[14], digest[15]
        ))
    }
}
