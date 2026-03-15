//
//  PolicySigner.swift
//  clearancekit-daemon
//
//  Signs and verifies the on-disk policy JSON using an EC-P256 key stored in
//  the data-protection keychain (kSecUseDataProtectionKeychain = true).
//
//  Key selection (in priority order):
//
//  1. Secure Enclave — hardware-bound, not exportable, inaccessible while the
//     machine is locked. Only the daemon can use the key; enforcement is at the
//     hardware level.
//
//  2. Software fallback — for Intel Macs without a Secure Enclave. Stored in
//     the data-protection keychain with kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
//     which binds the key to this device and makes it inaccessible before the
//     first post-boot unlock. Software keys cannot be hardware-restricted to a
//     single application — that guarantee requires Secure Enclave.
//
//  Both paths use kSecUseDataProtectionKeychain = true and no deprecated
//  SecKeychain* APIs. The legacy System Keychain family requires UI interaction
//  (errSecInteractionNotAllowed) in a daemon context and is not used here.
//

import Foundation
import Security

enum PolicySigner {
    private static let keyTag    = Data("uk.craigbass.clearancekit.policy-signing-key".utf8)
    private static let keyLabel  = "clearancekit policy signing key"
    private static let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

    // MARK: - Public API

    static func sign(_ data: Data) throws -> Data {
        let key = try loadOrCreateKey()
        var cfError: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, algorithm, data as CFData, &cfError) else {
            throw cfError!.takeRetainedValue()
        }
        return sig as Data
    }

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

    private static func loadKey() throws -> SecKey {
        let query: [CFString: Any] = [
            kSecClass:                     kSecClassKey,
            kSecAttrApplicationTag:        keyTag,
            kSecAttrKeyType:               kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass:              kSecAttrKeyClassPrivate,
            kSecUseDataProtectionKeychain: true,
            kSecReturnRef:                 true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let key = item else {
            throw PolicySignerError.keyNotFound(status)
        }
        return (key as! SecKey)
    }

    private static func createKey() throws -> SecKey {
        if let key = try? createSecureEnclaveKey() {
            NSLog("PolicySigner: Created Secure Enclave-backed EC-P256 signing key")
            return key
        }
        NSLog("PolicySigner: Secure Enclave unavailable — creating software-backed EC-P256 signing key")
        return try createSoftwareKey()
    }

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

    private static func createSoftwareKey() throws -> SecKey {
        guard let acl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [],
            nil
        ) else { throw PolicySignerError.aclCreationFailed }

        let attrs: [CFString: Any] = [
            kSecAttrKeyType:               kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits:         256,
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
}

// MARK: - PolicySignerError

enum PolicySignerError: Error {
    case keyNotFound(OSStatus)
    case publicKeyUnavailable
    case aclCreationFailed
    case verificationFailed
}
