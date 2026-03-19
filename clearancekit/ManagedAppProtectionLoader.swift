//
//  ManagedAppProtectionLoader.swift
//  clearancekit
//
//  Reads the managed AppProtections preference delivered via MDM or a manually
//  installed .mobileconfig profile. Uses CFPreferencesCopyAppValue which reads
//  the merged preferences layer including managed profiles.
//
//  Plist / mobileconfig schema — entry in the AppProtections array:
//
//    ID        (string, optional)  — stable UUID; omit to auto-derive from AppName.
//                                    Always generate with `uuidgen`, never invent values.
//    AppName   (string, required)  — display name shown in the clearancekit GUI.
//    BundleID  (string, optional)  — application bundle identifier, used to look
//                                    up the app icon when the app is installed locally.
//    RuleIDs   (array of strings)  — UUIDs of FAAPolicy rules (from the FAAPolicy
//                                    preference key) that belong to this protection.
//                                    Each UUID must match the ID of a FAAPolicy entry.
//                                    Always generate with `uuidgen`.
//

import AppKit
import CommonCrypto
import Foundation

enum ManagedAppProtectionLoader {
    private static let preferencesDomain: CFString = XPCConstants.bundleIDPrefix as CFString
    private static let appProtectionsKey: CFString = "AppProtections" as CFString

    /// UUID v5 namespace used when deriving stable protection IDs from an app name.
    /// This is the RFC 4122 URL namespace: 6ba7b811-9dad-11d1-80b4-00c04fd430c8
    private static let uuidV5Namespace = UUID(uuidString: "6BA7B811-9DAD-11D1-80B4-00C04FD430C8")!

    /// Reads the managed AppProtections from CFPreferences.
    static func load() -> [AppProtection] {
        guard let raw = CFPreferencesCopyAppValue(appProtectionsKey, preferencesDomain) as? [[String: Any]] else {
            return []
        }
        let protections = raw.compactMap(parse)
        NSLog("ManagedAppProtectionLoader: Loaded %d managed app protection(s)", protections.count)
        return protections
    }

    // MARK: - Private

    private static func parse(_ dict: [String: Any]) -> AppProtection? {
        guard let appName = dict["AppName"] as? String, !appName.isEmpty else {
            NSLog("ManagedAppProtectionLoader: Skipping entry with missing or empty AppName")
            return nil
        }

        guard let ruleIDStrings = dict["RuleIDs"] as? [String] else {
            NSLog("ManagedAppProtectionLoader: Skipping '%@' — missing RuleIDs", appName)
            return nil
        }

        let ruleIDs = ruleIDStrings.compactMap { UUID(uuidString: $0) }
        guard !ruleIDs.isEmpty else {
            NSLog("ManagedAppProtectionLoader: Skipping '%@' — no valid UUIDs in RuleIDs", appName)
            return nil
        }

        let id: UUID
        if let idString = dict["ID"] as? String, let parsed = UUID(uuidString: idString) {
            id = parsed
        } else {
            id = deterministicID(for: appName)
        }

        let bundleID = dict["BundleID"] as? String ?? ""

        return AppProtection(
            id: id,
            appName: appName,
            appBundlePath: appBundlePath(for: bundleID),
            bundleID: bundleID,
            ruleIDs: ruleIDs,
            // MDM-delivered protections are always active — they are enforced by
            // the FAAPolicy rules they reference and cannot be toggled in the GUI.
            isEnabled: true,
            snapshotRules: nil
        )
    }

    private static func appBundlePath(for bundleID: String) -> String {
        guard !bundleID.isEmpty else { return "" }
        return NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID)?.path ?? ""
    }

    /// Derives a stable UUID v5 (RFC 4122, SHA-1) for a protection when no explicit
    /// ID is provided. The name is the UTF-8 encoding of the AppName.
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
