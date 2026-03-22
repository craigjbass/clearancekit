//
//  SecureEnclaveStore.swift
//  Shared
//
//  Domain types for Secure Enclave SSH key management.
//
//  Portions of this file are derived from Secretive by Max Goedjen.
//  Original license follows:
//
//  MIT License
//
//  Copyright (c) 2020 Max Goedjen
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//
//  FEASIBILITY NOTES
//  =================
//  The Secure Enclave is only accessible from user-space processes. The opfilter
//  system extension (which runs as root in kernel context) CANNOT access the
//  Secure Enclave — this is a platform constraint documented in PolicySigner.swift.
//
//  This means the SSH agent must run in the clearancekit GUI app (or a dedicated
//  user-space helper) rather than in opfilter. The domain types below define
//  the protocol boundary so that the adapter layer can provide concrete
//  implementations without leaking CryptoKit or Security.framework into
//  domain code.
//
//  DIFFICULT AREAS
//  ===============
//  1. Secure Enclave from system extension — NOT POSSIBLE. The agent must live
//     in user-space. This splits the trust boundary: opfilter enforces file
//     access policy, while a separate process manages cryptographic keys.
//
//  2. Key persistence across reboots — Secure Enclave keys created with
//     CryptoKit's SecureEnclave.P256 are hardware-bound and survive reboots,
//     but cannot be exported. Re-enrollment with remote hosts is required if
//     the key is deleted or the hardware changes.
//
//  3. SSH agent socket lifecycle — The agent socket (SSH_AUTH_SOCK) must be
//     available before SSH clients launch. On macOS this typically requires
//     a LaunchAgent plist, adding deployment complexity.
//
//  4. Multiple key types — The Secure Enclave only supports NIST P-256.
//     P-384 keys would require a software fallback (similar to Secretive's
//     approach) which weakens the hardware-backed security guarantee.
//

import Foundation

// MARK: - SSHKeyType

enum SSHKeyType: String, Codable, Equatable {
    case secureEnclaveP256
    case softwareP384
}

// MARK: - SSHKeyMetadata

struct SSHKeyMetadata: Identifiable, Equatable {
    let id: UUID
    let name: String
    let keyType: SSHKeyType
    let algorithm: SSHKeyAlgorithm
    let publicKeyData: Data
    let createdAt: Date

    var authorizedKeysEntry: String {
        let blob = SSHAgentWireFormat.encodePublicKeyBlob(
            algorithm: algorithm,
            publicKeyBytes: publicKeyData
        )
        return "\(algorithm.rawValue) \(blob.base64EncodedString()) \(name)"
    }
}

// MARK: - KeyStoreError

enum KeyStoreError: Error {
    case keyGenerationFailed
    case keyNotFound(UUID)
    case signingFailed
    case secureEnclaveUnavailable
    case authenticationRequired
}

// MARK: - KeyStoreProtocol

protocol KeyStoreProtocol: Sendable {
    func listKeys() -> [SSHKeyMetadata]
    func createKey(name: String, type: SSHKeyType) throws -> SSHKeyMetadata
    func deleteKey(id: UUID) throws
    func sign(data: Data, withKeyID keyID: UUID, authentication: @Sendable () async throws -> Void) async throws -> Data
}
