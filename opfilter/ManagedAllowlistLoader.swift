//
//  ManagedAllowlistLoader.swift
//  opfilter
//
//  Reads the managed GlobalAllowlist preference delivered via MDM or a manually
//  installed .mobileconfig profile. Follows the same CFPreferencesCopyAppValue
//  pattern as ManagedPolicyLoader.
//
//  Plist / mobileconfig schema — entry in the GlobalAllowlist array:
//
//    ID             (string, optional)  — stable UUID string; omit to auto-derive
//    SigningID      (string)            — match by signing ID; OR
//    ProcessPath    (string)            — match by executable path
//    PlatformBinary (bool)              — if true, process must have empty team ID
//    TeamID         (string, optional)  — additional team constraint when !PlatformBinary
//

import Foundation
import CommonCrypto

enum ManagedAllowlistLoader {
    private static let preferencesDomain: CFString = XPCConstants.bundleIDPrefix as CFString
    private static let allowlistKey: CFString = "GlobalAllowlist" as CFString
    private static let uuidV5Namespace = UUID(uuidString: "6BA7B811-9DAD-11D1-80B4-00C04FD430C8")!

    static func load() -> [AllowlistEntry] {
        guard let raw = CFPreferencesCopyAppValue(allowlistKey, preferencesDomain) as? [[String: Any]] else {
            NSLog("ManagedAllowlistLoader: No managed GlobalAllowlist found — running without managed allowlist tier")
            return []
        }
        let entries = raw.compactMap(parseEntry)
        NSLog("ManagedAllowlistLoader: Loaded %d managed allowlist entry/entries", entries.count)
        return entries
    }

    static func loadWithSync() -> [AllowlistEntry] {
        CFPreferencesAppSynchronize(preferencesDomain)
        return load()
    }

    // MARK: - Private

    private static func parseEntry(_ dict: [String: Any]) -> AllowlistEntry? {
        let signingID   = dict["SigningID"]   as? String ?? ""
        let processPath = dict["ProcessPath"] as? String ?? ""
        guard !signingID.isEmpty || !processPath.isEmpty else {
            NSLog("ManagedAllowlistLoader: Skipping entry with no SigningID or ProcessPath")
            return nil
        }

        let platformBinary = dict["PlatformBinary"] as? Bool ?? false
        let teamID = dict["TeamID"] as? String ?? ""

        let id: UUID
        if let idString = dict["ID"] as? String, let parsed = UUID(uuidString: idString) {
            id = parsed
        } else {
            id = deterministicID(for: signingID.isEmpty ? processPath : signingID)
        }

        return AllowlistEntry(
            id: id,
            signingID: signingID,
            processPath: processPath,
            platformBinary: platformBinary,
            teamID: teamID
        )
    }

    private static func deterministicID(for name: String) -> UUID {
        var nsBytes = uuidV5Namespace.uuid
        let nameBytes = Array(name.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        var ctx = CC_SHA1_CTX()
        CC_SHA1_Init(&ctx)
        withUnsafeBytes(of: &nsBytes) { ptr in
            _ = CC_SHA1_Update(&ctx, ptr.baseAddress, CC_LONG(ptr.count))
        }
        CC_SHA1_Update(&ctx, nameBytes, CC_LONG(nameBytes.count))
        CC_SHA1_Final(&digest, &ctx)
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
