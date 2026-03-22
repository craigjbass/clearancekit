//
//  SSHAgent.swift
//  Shared
//
//  SSH agent wire protocol types (RFC draft-miller-ssh-agent).
//  These types model the subset of the agent protocol needed for
//  Secure-Enclave-backed key operations: listing identities and signing.
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

import Foundation

// MARK: - SSHAgentMessageType

enum SSHAgentMessageType: UInt8 {
    case requestIdentities = 11
    case identitiesAnswer = 12
    case signRequest = 13
    case signResponse = 14
    case failure = 5
    case success = 6
}

// MARK: - SSHKeyAlgorithm

enum SSHKeyAlgorithm: String {
    case ecdsaSHA2P256 = "ecdsa-sha2-nistp256"
    case ecdsaSHA2P384 = "ecdsa-sha2-nistp384"

    var curveName: String {
        switch self {
        case .ecdsaSHA2P256: return "nistp256"
        case .ecdsaSHA2P384: return "nistp384"
        }
    }

    var keyBitSize: Int {
        switch self {
        case .ecdsaSHA2P256: return 256
        case .ecdsaSHA2P384: return 384
        }
    }
}

// MARK: - SSHKeyIdentity

struct SSHKeyIdentity: Equatable {
    let publicKeyBlob: Data
    let comment: String
}

// MARK: - SSHAgentRequest

enum SSHAgentRequest {
    case requestIdentities
    case signRequest(publicKeyBlob: Data, dataToSign: Data, flags: UInt32)
}

// MARK: - SSHAgentResponse

enum SSHAgentResponse {
    case identitiesAnswer(identities: [SSHKeyIdentity])
    case signResponse(signature: Data)
    case failure
}

// MARK: - SSHAgentWireFormat

enum SSHAgentWireFormat {
    enum ParseError: Error {
        case messageTooShort
        case unsupportedMessageType(UInt8)
        case invalidPayload
    }

    static func parseRequest(from data: Data) throws -> SSHAgentRequest {
        guard data.count >= 1 else { throw ParseError.messageTooShort }
        let typeByte = data[data.startIndex]
        guard let messageType = SSHAgentMessageType(rawValue: typeByte) else {
            throw ParseError.unsupportedMessageType(typeByte)
        }
        switch messageType {
        case .requestIdentities:
            return .requestIdentities
        case .signRequest:
            return try parseSignRequest(data.dropFirst())
        default:
            throw ParseError.unsupportedMessageType(typeByte)
        }
    }

    static func encodeResponse(_ response: SSHAgentResponse) -> Data {
        switch response {
        case .identitiesAnswer(let identities):
            return encodeIdentitiesAnswer(identities)
        case .signResponse(let signature):
            return encodeSignResponse(signature)
        case .failure:
            return Data([SSHAgentMessageType.failure.rawValue])
        }
    }

    // MARK: - Encoding public key blobs

    static func encodePublicKeyBlob(algorithm: SSHKeyAlgorithm, publicKeyBytes: Data) -> Data {
        var blob = Data()
        appendSSHString(algorithm.rawValue, to: &blob)
        appendSSHString(algorithm.curveName, to: &blob)
        appendSSHBytes(publicKeyBytes, to: &blob)
        return blob
    }

    // MARK: - Private parsing helpers

    private static func parseSignRequest(_ payload: Data) throws -> SSHAgentRequest {
        var offset = payload.startIndex
        let keyBlob = try readSSHBytes(from: payload, at: &offset)
        let signData = try readSSHBytes(from: payload, at: &offset)
        let flags = try readUInt32(from: payload, at: &offset)
        return .signRequest(publicKeyBlob: keyBlob, dataToSign: signData, flags: flags)
    }

    // MARK: - Private encoding helpers

    private static func encodeIdentitiesAnswer(_ identities: [SSHKeyIdentity]) -> Data {
        var result = Data()
        result.append(SSHAgentMessageType.identitiesAnswer.rawValue)
        appendUInt32(UInt32(identities.count), to: &result)
        for identity in identities {
            appendSSHBytes(identity.publicKeyBlob, to: &result)
            appendSSHString(identity.comment, to: &result)
        }
        return result
    }

    private static func encodeSignResponse(_ signature: Data) -> Data {
        var result = Data()
        result.append(SSHAgentMessageType.signResponse.rawValue)
        appendSSHBytes(signature, to: &result)
        return result
    }

    // MARK: - Wire format primitives

    static func readUInt32(from data: Data, at offset: inout Data.Index) throws -> UInt32 {
        guard offset + 4 <= data.endIndex else { throw ParseError.invalidPayload }
        let value = UInt32(data[offset]) << 24
            | UInt32(data[offset + 1]) << 16
            | UInt32(data[offset + 2]) << 8
            | UInt32(data[offset + 3])
        offset += 4
        return value
    }

    static func readSSHBytes(from data: Data, at offset: inout Data.Index) throws -> Data {
        let length = try readUInt32(from: data, at: &offset)
        guard offset + Int(length) <= data.endIndex else { throw ParseError.invalidPayload }
        let bytes = data[offset..<(offset + Int(length))]
        offset += Int(length)
        return Data(bytes)
    }

    static func appendUInt32(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    static func appendSSHBytes(_ bytes: Data, to data: inout Data) {
        appendUInt32(UInt32(bytes.count), to: &data)
        data.append(bytes)
    }

    static func appendSSHString(_ string: String, to data: inout Data) {
        appendSSHBytes(Data(string.utf8), to: &data)
    }
}
