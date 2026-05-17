//
//  PolicySigner.swift
//  opfilter
//
//  Signs and verifies the on-disk policy JSON using an EC-P256 key.
//
//  Requirements:
//    - ACL locked down to the opfilter process only
//    - Stored in the System Keychain
//
//  Secure Enclave is not accessible from system-level processes. The SE is
//  accessed via com.apple.ctkd.token-client, a per-user LaunchAgent —
//  system extensions run in the system context and cannot reach it.
//
//  Implementation: software EC-P256 key in the System Keychain with a
//  SecAccess ACL restricting usage to opfilter. The SecKeychain APIs are
//  deprecated but remain the only reliable keychain for root processes;
//  the data-protection keychain is per-user and unsuitable here.
//

import Foundation
import Security

/// Legacy marker files used by earlier opfilter builds to track ACL-migration
/// state on disk. They are now ignored — the keychain version counter is the
/// sole trust anchor — but we still clean them up on first v3 boot to avoid
/// leaving stale state in /Library/Application Support/clearancekit.
private let legacyAclMarkers: [URL] = [
    URL(fileURLWithPath: "/Library/Application Support/clearancekit/.key-acl-v2"),
    URL(fileURLWithPath: "/Library/Application Support/clearancekit/.key-acl-v3"),
]

enum PolicySigner {
    private static let keyTag    = Data("uk.craigbass.clearancekit.policy-signing-key".utf8)
    private static let keyLabel  = "clearancekit policy signing key"
    private static let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

    /// Generic-password keychain item that records which ACL-migration version
    /// has run. Trust anchor for skipping the marker-file path on subsequent
    /// boots: once written with a proper ACL it can only be modified by
    /// opfilter, so an attacker cannot force re-migration by deleting the
    /// marker file alone.
    private static let aclVersionService = "uk.craigbass.clearancekit.acl-version"
    private static let aclVersionAccount = "policy-signing-key"
    /// Bumped to 4 because the v3 migration used a two-step
    /// `SecKeyCreateRandomKey` + `SecItemAdd(kSecAttrAccess:)` flow, and
    /// `kSecAttrAccess` is silently ignored for `kSecClassKey` items added
    /// that way — the persisted key ended up with an unrestricted ACL.
    /// v4 creates and persists the key in a single `SecKeyCreateRandomKey`
    /// call with `kSecAttrIsPermanent:true` and `kSecAttrAccess` in the
    /// same attrs dict, which does correctly bind the ACL.
    private static let currentAclMigrationVersion = 4

    /// Reference to the System Keychain, used for software-backed keys only.
    ///
    /// `SecKeychainOpen` is deprecated since macOS 10.10 but remains the only API that
    /// accepts an explicit keychain path. `SecItemCopyMatching` does not accept a path, so
    /// the legacy API is required here; the deprecation warning is accepted as known noise.
    private static let systemKeychain: SecKeychain? = {
        var kc: SecKeychain?
        // SecKeychainOpen is deprecated (macOS 10.10) but has no modern replacement for
        // explicit keychain paths; the warning is expected and intentional.
        let status = SecKeychainOpen("/Library/Keychains/System.keychain", &kc)
        if status != errSecSuccess {
            NSLog("PolicySigner: Could not open System Keychain (%d)", status)
        }
        return kc
    }()

    // MARK: - Public API

    static func sign(_ data: Data) throws -> Data {
        let key = try loadOrCreateKey()
        var cfError: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, algorithm, data as CFData, &cfError) else {
            throw cfError!.takeRetainedValue()
        }
        return sig as Data
    }

    /// Throws if the signature does not match the data.
    static func verify(_ data: Data, signature: Data) throws {
        let key = try loadOrCreateKey()
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw PolicySignerError.publicKeyUnavailable
        }
        var cfError: Unmanaged<CFError>?
        guard SecKeyVerifySignature(
            publicKey, algorithm,
            data as CFData, signature as CFData,
            &cfError
        ) else {
            throw cfError?.takeRetainedValue() ?? PolicySignerError.verificationFailed
        }
    }

    // MARK: - Key lifecycle

    static func loadOrCreateKey() throws -> SecKey {
        if let key = try? loadKey() { return key }
        return try createSoftwareKey()
    }

    /// Verifies `signature` against `data` using the currently-loaded signing
    /// key and reports the result as a Bool, without throwing. Used by
    /// `migrateAclIfNeeded` to capture tables whose existing signature is
    /// valid under the old (about-to-be-rotated) key.
    static func canVerify(_ data: Data, signature: Data) -> Bool {
        (try? verify(data, signature: signature)) != nil
    }

    /// Forces the next call to `loadOrCreateKey` to mint a fresh key by
    /// deleting any existing one. Used only by `migrateAclIfNeeded` after the
    /// caller has already captured everything they want to re-sign under the
    /// new key.
    static func rotateKey() {
        var query: [CFString: Any] = [
            kSecClass:              kSecClassKey,
            kSecAttrApplicationTag: keyTag,
            kSecAttrKeyType:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass:       kSecAttrKeyClassPrivate,
        ]
        if let kc = systemKeychain { query[kSecUseKeychain] = kc }

        let status = SecItemDelete(query as CFDictionary)
        switch status {
        case errSecSuccess:
            NSLog("PolicySigner: Rotated System Keychain key")
        case errSecItemNotFound:
            NSLog("PolicySigner: rotateKey — no existing key")
        default:
            NSLog("PolicySigner: SecItemDelete during rotateKey failed (%d)", status)
        }
    }

    static func aclMigrationVersion() -> Int { readAclMigrationVersion() }
    static func currentAclVersion() -> Int { currentAclMigrationVersion }
    static func recordAclMigrationVersion() {
        for marker in legacyAclMarkers { try? FileManager.default.removeItem(at: marker) }
        writeAclMigrationVersion(currentAclMigrationVersion)
    }

    private static func loadKey() throws -> SecKey {
        var query: [CFString: Any] = [
            kSecClass:              kSecClassKey,
            kSecAttrApplicationTag: keyTag,
            kSecAttrKeyType:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass:       kSecAttrKeyClassPrivate,
            kSecReturnRef:          true,
        ]
        if let kc = systemKeychain { query[kSecUseKeychain] = kc }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let key = item else {
            throw PolicySignerError.keyNotFound(status)
        }
        return (key as! SecKey)
    }

    /// Software-backed key stored in the System Keychain with an opfilter-only
    /// ACL. The key is created and persisted in a single `SecKeyCreateRandomKey`
    /// call: passing `kSecAttrIsPermanent: true` plus `kSecAttrAccess` and
    /// `kSecUseKeychain` together binds the access at storage time. The
    /// previously-used two-step `SecKeyCreateRandomKey` + `SecItemAdd` flow
    /// silently produced an unrestricted ACL because `kSecAttrAccess` on
    /// `SecItemAdd(kSecValueRef:)` is observed to be ignored for
    /// `kSecClassKey` items in the legacy System.keychain.
    private static func createSoftwareKey() throws -> SecKey {
        let access = try makeDaemonOnlyAccess()

        var attrs: [CFString: Any] = [
            kSecAttrKeyType:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits:  256,
            kSecAttrIsPermanent:    true,
            kSecAttrApplicationTag: keyTag,
            kSecAttrLabel:          keyLabel,
            kSecAttrAccess:         access,
        ]
        if let kc = systemKeychain { attrs[kSecUseKeychain] = kc }

        var cfError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &cfError) else {
            throw cfError!.takeRetainedValue()
        }
        NSLog("PolicySigner: Created and stored software key in System Keychain with opfilter-only ACL")
        return key
    }

    /// Builds a SecAccess that lists only opfilter as a trusted application,
    /// resolved via the running executable's absolute path. Passing `nil` to
    /// `SecTrustedApplicationCreateFromPath` was observed to produce an
    /// empty trusted-apps list when called from a system extension; the
    /// explicit path forces the API to bind to the running binary's CDHash.
    private static func makeDaemonOnlyAccess() throws -> SecAccess {
        let executablePath = currentExecutablePath()
        var trustedApp: SecTrustedApplication?
        let appStatus = SecTrustedApplicationCreateFromPath(executablePath, &trustedApp)
        guard appStatus == errSecSuccess, let app = trustedApp else {
            NSLog("PolicySigner: SecTrustedApplicationCreateFromPath failed for %@ (%d)", executablePath, appStatus)
            throw PolicySignerError.aclCreationFailed
        }

        var access: SecAccess?
        let accessStatus = SecAccessCreate(keyLabel as CFString, [app] as CFArray, &access)
        guard accessStatus == errSecSuccess, let result = access else {
            NSLog("PolicySigner: SecAccessCreate failed (%d)", accessStatus)
            throw PolicySignerError.aclCreationFailed
        }
        return result
    }

    private static func currentExecutablePath() -> String {
        var size: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &size)
        var buffer = [CChar](repeating: 0, count: Int(size))
        let status = _NSGetExecutablePath(&buffer, &size)
        guard status == 0 else {
            fatalError("PolicySigner: _NSGetExecutablePath failed (\(status)) — cannot bind keychain ACL to opfilter")
        }
        return String(cString: buffer)
    }

    // MARK: - ACL migration version counter

    private static func readAclMigrationVersion() -> Int {
        var query: [CFString: Any] = [
            kSecClass:          kSecClassGenericPassword,
            kSecAttrService:    aclVersionService,
            kSecAttrAccount:    aclVersionAccount,
            kSecReturnData:     true,
        ]
        if let kc = systemKeychain { query[kSecMatchSearchList] = [kc] as CFArray }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return 0 }
        return Int(String(data: data, encoding: .utf8) ?? "0") ?? 0
    }

    private static func writeAclMigrationVersion(_ version: Int) {
        let data = Data(String(version).utf8)

        var matchQuery: [CFString: Any] = [
            kSecClass:          kSecClassGenericPassword,
            kSecAttrService:    aclVersionService,
            kSecAttrAccount:    aclVersionAccount,
        ]
        if let kc = systemKeychain { matchQuery[kSecMatchSearchList] = [kc] as CFArray }

        let update: [CFString: Any] = [kSecValueData: data]
        let updateStatus = SecItemUpdate(matchQuery as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess {
            NSLog("PolicySigner: Updated ACL migration version to %d in System Keychain", version)
            return
        }
        guard updateStatus == errSecItemNotFound else {
            NSLog("PolicySigner: SecItemUpdate failed for ACL version counter (%d)", updateStatus)
            return
        }

        guard let access = try? makeDaemonOnlyAccess() else {
            NSLog("PolicySigner: Could not build ACL for migration version counter")
            return
        }

        var addQuery: [CFString: Any] = [
            kSecClass:          kSecClassGenericPassword,
            kSecAttrService:    aclVersionService,
            kSecAttrAccount:    aclVersionAccount,
            kSecValueData:      data,
            kSecAttrAccess:     access,
        ]
        if let kc = systemKeychain { addQuery[kSecUseKeychain] = kc }

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess {
            NSLog("PolicySigner: Wrote ACL migration version=%d to System Keychain with opfilter-only ACL", version)
        } else {
            NSLog("PolicySigner: SecItemAdd failed for ACL version counter (%d)", addStatus)
        }
    }
}

// MARK: - PolicySignerError

enum PolicySignerError: Error {
    case keyNotFound(OSStatus)
    case keyStoreFailed(OSStatus)
    case publicKeyUnavailable
    case aclCreationFailed
    case verificationFailed
}
