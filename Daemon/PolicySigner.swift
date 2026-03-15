//
//  PolicySigner.swift
//  clearancekit-daemon
//
//  Signs and verifies the on-disk policy JSON using an EC-P256 key stored in
//  the System Keychain.
//
//  Key selection (in priority order):
//
//  1. Secure Enclave — hardware-bound, not exportable, inaccessible while the
//     machine is locked. Stored via the data-protection keychain
//     (kSecUseDataProtectionKeychain) which is the required storage backend for
//     SE keys on macOS. kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly means
//     the key is accessible after the first unlock and is bound to this device.
//
//  2. Software fallback — for Intel Macs without a T2 chip. Explicitly stored
//     in the System Keychain (/Library/Keychains/System.keychain) rather than
//     any per-user login keychain. Scoped via SecTrustedApplicationCreateFromPath
//     so only processes sharing the daemon's code-signing identity (team
//     37KMK6XFTT) can use the key.
//
//  Keychain targeting:
//  - SE path:       kSecUseDataProtectionKeychain = true
//  - Software path: explicit SecKeychainOpen("/Library/Keychains/System.keychain")
//  Both are searched on load so the correct key is found regardless of which
//  path was used at creation time.
//

import Foundation
import Security

enum PolicySigner {
    private static let keyTag    = Data("uk.craigbass.clearancekit.policy-signing-key".utf8)
    private static let keyLabel  = "clearancekit policy signing key"
    private static let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

    /// Reference to the System Keychain. Used for software-backed keys so they
    /// are never accidentally stored in a per-user login keychain.
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
        if let key = try? loadKey() { return key }
        return try createKey()
    }

    /// Searches the data-protection keychain (SE keys) then the System Keychain
    /// (software keys) so the correct key is found regardless of creation path.
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
        migrateSystemKeychainACL()
        return (key as! SecKey)
    }

    /// Updates the ACL of an existing System Keychain key to daemon-only in-place,
    /// preserving the key material so existing signatures remain valid.
    private static func migrateSystemKeychainACL() {
        guard let access = makeDaemonOnlyACL() else {
            NSLog("PolicySigner: ACL migration skipped — could not build daemon-only ACL")
            return
        }
        var searchQuery: [CFString: Any] = [
            kSecClass:              kSecClassKey,
            kSecAttrApplicationTag: keyTag,
            kSecAttrKeyType:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass:       kSecAttrKeyClassPrivate,
        ]
        if let kc = systemKeychain { searchQuery[kSecUseKeychain] = kc }
        let updateStatus = SecItemUpdate(
            searchQuery as CFDictionary,
            [kSecAttrAccess: access] as CFDictionary
        )
        switch updateStatus {
        case errSecSuccess:
            NSLog("PolicySigner: Migrated System Keychain key ACL to daemon-only")
        case errSecItemNotFound:
            break
        default:
            NSLog("PolicySigner: ACL migration failed (%d) — key remains with existing ACL", updateStatus)
        }
    }

    private static func createKey() throws -> SecKey {
        if let key = try? createSecureEnclaveKey() {
            NSLog("PolicySigner: Created Secure Enclave-backed EC-P256 signing key")
            return key
        }
        NSLog("PolicySigner: Secure Enclave unavailable — creating software-backed EC-P256 signing key in System Keychain")
        return try createSoftwareKey()
    }

    /// Secure Enclave key stored via the data-protection keychain backend.
    /// kSecUseDataProtectionKeychain is required for SE keys on macOS; without
    /// it SecKeyCreateRandomKey may fail or store the reference incorrectly.
    private static func createSecureEnclaveKey() throws -> SecKey {
        guard let acl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            nil
        ) else { throw PolicySignerError.aclCreationFailed }

        let attrs: [CFString: Any] = [
            kSecAttrKeyType:              kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits:        256,
            kSecAttrTokenID:              kSecAttrTokenIDSecureEnclave,
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

    /// Software-backed key stored explicitly in the System Keychain.
    /// Creates the key in memory first, then uses SecItemAdd with an explicit
    /// System Keychain reference so it never lands in a per-user login keychain.
    /// ACL restricted to the daemon executable only via SecTrustedApplicationCreateFromPath.
    private static func createSoftwareKey() throws -> SecKey {
        let keyAttrs: [CFString: Any] = [
            kSecAttrKeyType:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
        ]
        var cfError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(keyAttrs as CFDictionary, &cfError) else {
            throw cfError!.takeRetainedValue()
        }

        var addQuery: [CFString: Any] = [
            kSecClass:              kSecClassKey,
            kSecValueRef:           key,
            kSecAttrApplicationTag: keyTag,
            kSecAttrLabel:          keyLabel,
        ]
        if let access = makeDaemonOnlyACL() {
            addQuery[kSecAttrAccess] = access
        } else {
            throw PolicySignerError.aclCreationFailed
        }
        if let kc = systemKeychain { addQuery[kSecUseKeychain] = kc }

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw PolicySignerError.keyStoreFailed(status)
        }
        return key
    }

    /// Builds a SecAccess that restricts key usage to the daemon executable.
    /// Uses the daemon's own path rather than nil so the ACL names the specific
    /// binary, not an implicit "current process" that may resolve incorrectly for
    /// non-bundle tools and silently falls back to allow-all.
    private static func makeDaemonOnlyACL() -> SecAccess? {
        guard let executablePath = Bundle.main.executablePath else {
            NSLog("PolicySigner: Could not determine daemon executable path for ACL")
            return nil
        }
        var trustedApp: SecTrustedApplication?
        let appStatus = SecTrustedApplicationCreateFromPath(executablePath, &trustedApp)
        guard appStatus == errSecSuccess, let app = trustedApp else {
            NSLog("PolicySigner: SecTrustedApplicationCreateFromPath failed (%d)", appStatus)
            return nil
        }
        var secAccess: SecAccess?
        let accessStatus = SecAccessCreate(keyLabel as CFString, [app] as CFArray, &secAccess)
        guard accessStatus == errSecSuccess, let access = secAccess else {
            NSLog("PolicySigner: SecAccessCreate failed (%d)", accessStatus)
            return nil
        }
        return access
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
