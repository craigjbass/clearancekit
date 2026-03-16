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

private let aclMigrationMarker = URL(fileURLWithPath: "/Library/Application Support/clearancekit/.key-acl-v2")

enum PolicySigner {
    private static let keyTag    = Data("uk.craigbass.clearancekit.policy-signing-key".utf8)
    private static let keyLabel  = "clearancekit policy signing key"
    private static let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

    /// Reference to the System Keychain, used for software-backed keys only.
    private static let systemKeychain: SecKeychain? = {
        var kc: SecKeychain?
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
        migratePermissiveKeyOnce()
        if let key = try? loadKey() { return key }
        return try createSoftwareKey()
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

    /// Software-backed key stored in the System Keychain with a opfilter-only ACL.
    /// The key is created in memory first, then stored via SecItemAdd with an
    /// explicit System Keychain reference and a SecAccess restricting usage to
    /// the current process (opfilter).
    private static func createSoftwareKey() throws -> SecKey {
        let keyAttrs: [CFString: Any] = [
            kSecAttrKeyType:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
        ]
        var cfError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(keyAttrs as CFDictionary, &cfError) else {
            throw cfError!.takeRetainedValue()
        }

        let access = try makeDaemonOnlyAccess()

        var addQuery: [CFString: Any] = [
            kSecClass:              kSecClassKey,
            kSecValueRef:           key,
            kSecAttrApplicationTag: keyTag,
            kSecAttrLabel:          keyLabel,
            kSecAttrAccess:         access,
        ]
        if let kc = systemKeychain { addQuery[kSecUseKeychain] = kc }

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw PolicySignerError.keyStoreFailed(status)
        }
        NSLog("PolicySigner: Stored software key in System Keychain with opfilter-only ACL")
        return key
    }

    /// Builds a SecAccess that lists only opfilter as a trusted application.
    /// In Keychain Access this shows as "Confirm before allowing access" with
    /// opfilter under "Always allow access by these applications".
    private static func makeDaemonOnlyAccess() throws -> SecAccess {
        var trustedApp: SecTrustedApplication?
        let appStatus = SecTrustedApplicationCreateFromPath(nil, &trustedApp)
        guard appStatus == errSecSuccess, let app = trustedApp else {
            NSLog("PolicySigner: SecTrustedApplicationCreateFromPath failed (%d)", appStatus)
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

    // MARK: - One-time migration

    /// Deletes any existing System Keychain key that was created with a
    /// permissive (allow-all) ACL. Runs once, gated by a marker file.
    /// The next call to loadOrCreateKey() will create a fresh key with a
    /// opfilter-only ACL.
    private static func migratePermissiveKeyOnce() {
        guard !FileManager.default.fileExists(atPath: aclMigrationMarker.path) else { return }
        defer {
            FileManager.default.createFile(atPath: aclMigrationMarker.path, contents: nil)
        }

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
            NSLog("PolicySigner: Deleted old System Keychain key with permissive ACL")
        case errSecItemNotFound:
            NSLog("PolicySigner: No old System Keychain key to migrate")
        default:
            NSLog("PolicySigner: Could not delete old key (%d) — it may need manual removal from Keychain Access", status)
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
