//
//  PolicySigner.swift
//  clearancekit-daemon
//
//  Signs and verifies the on-disk policy JSON using an EC-P256 key.
//
//  Key selection (in priority order):
//
//  1. Secure Enclave — hardware-bound, not exportable, inaccessible while the
//     machine is locked. Stored via the data-protection keychain
//     (kSecUseDataProtectionKeychain). Requires the keychain-access-groups
//     entitlement so the daemon has a valid keychain identity.
//
//  2. Software fallback — for Intel Macs without a Secure Enclave. Stored in
//     the System Keychain (/Library/Keychains/System.keychain) with an ACL
//     restricting usage to the daemon process. The SecKeychain APIs are
//     deprecated but remain the only reliable keychain for root LaunchDaemons;
//     the data-protection keychain is per-user and unsuitable for system daemons.
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
        return try createKey()
    }

    /// Searches the data-protection keychain (SE keys) then the System Keychain
    /// (software keys) so the correct key is found regardless of which path was
    /// used at creation time.
    private static func loadKey() throws -> SecKey {
        let baseQuery: [CFString: Any] = [
            kSecClass:              kSecClassKey,
            kSecAttrApplicationTag: keyTag,
            kSecAttrKeyType:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass:       kSecAttrKeyClassPrivate,
            kSecReturnRef:          true,
        ]

        // 1. Data-protection keychain — where SE keys are stored.
        var dpQuery = baseQuery
        dpQuery[kSecUseDataProtectionKeychain] = true
        var item: CFTypeRef?
        if SecItemCopyMatching(dpQuery as CFDictionary, &item) == errSecSuccess,
           let key = item {
            return (key as! SecKey)
        }

        // 2. System Keychain — where software-backed keys are stored.
        var sysQuery = baseQuery
        if let kc = systemKeychain { sysQuery[kSecUseKeychain] = kc }
        item = nil
        let status = SecItemCopyMatching(sysQuery as CFDictionary, &item)
        guard status == errSecSuccess, let key = item else {
            throw PolicySignerError.keyNotFound(status)
        }
        return (key as! SecKey)
    }

    private static func createKey() throws -> SecKey {
        do {
            let key = try createSecureEnclaveKey()
            NSLog("PolicySigner: Created Secure Enclave-backed EC-P256 signing key")
            return key
        } catch {
            NSLog("PolicySigner: Secure Enclave key creation failed: %@", "\(error)")
        }
        NSLog("PolicySigner: Falling back to software-backed EC-P256 key in System Keychain")
        return try createSoftwareKey()
    }

    /// Secure Enclave key stored via the data-protection keychain backend.
    private static func createSecureEnclaveKey() throws -> SecKey {
        guard let acl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            nil
        ) else { throw PolicySignerError.aclCreationFailed }

        let attrs: [CFString: Any] = [
            kSecAttrKeyType:               kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits:         256,
            kSecAttrTokenID:               kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain: true,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent:    true,
                kSecAttrApplicationTag: keyTag,
                kSecAttrLabel:          keyLabel,
                kSecAttrAccessControl:  acl,
            ] as [CFString: Any],
        ]
        var cfError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &cfError) else {
            throw cfError!.takeRetainedValue()
        }
        return key
    }

    /// Software-backed key stored in the System Keychain with a daemon-only ACL.
    /// The key is created in memory first, then stored via SecItemAdd with an
    /// explicit System Keychain reference and a SecAccess restricting usage to
    /// the current process (the daemon).
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
        NSLog("PolicySigner: Stored software key in System Keychain with daemon-only ACL")
        return key
    }

    /// Builds a SecAccess that lists only the daemon as a trusted application.
    /// In Keychain Access this shows as "Confirm before allowing access" with
    /// the daemon under "Always allow access by these applications".
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
    /// daemon-only ACL (or use the Secure Enclave if available).
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
