//
//  SSHAgentTests.swift
//  clearancekitTests
//

import Testing
import Foundation

// MARK: - SSHKeyAlgorithm

@Suite("SSHKeyAlgorithm")
struct SSHKeyAlgorithmTests {
    @Test("P256 algorithm has correct raw value and curve name")
    func p256Properties() {
        let alg = SSHKeyAlgorithm.ecdsaSHA2P256
        #expect(alg.rawValue == "ecdsa-sha2-nistp256")
        #expect(alg.curveName == "nistp256")
        #expect(alg.keyBitSize == 256)
    }

    @Test("P384 algorithm has correct raw value and curve name")
    func p384Properties() {
        let alg = SSHKeyAlgorithm.ecdsaSHA2P384
        #expect(alg.rawValue == "ecdsa-sha2-nistp384")
        #expect(alg.curveName == "nistp384")
        #expect(alg.keyBitSize == 384)
    }
}

// MARK: - Wire format primitives

@Suite("SSHAgentWireFormat primitives")
struct SSHAgentWireFormatPrimitivesTests {
    @Test("appendUInt32 and readUInt32 round-trip")
    func uint32RoundTrip() throws {
        var buffer = Data()
        SSHAgentWireFormat.appendUInt32(0x01020304, to: &buffer)

        #expect(buffer.count == 4)
        #expect(buffer == Data([0x01, 0x02, 0x03, 0x04]))

        var offset = buffer.startIndex
        let decoded = try SSHAgentWireFormat.readUInt32(from: buffer, at: &offset)
        #expect(decoded == 0x01020304)
    }

    @Test("readUInt32 throws on short data")
    func uint32ThrowsOnShortData() {
        let data = Data([0x01, 0x02])
        var offset = data.startIndex

        #expect(throws: SSHAgentWireFormat.ParseError.self) {
            _ = try SSHAgentWireFormat.readUInt32(from: data, at: &offset)
        }
    }

    @Test("appendSSHBytes and readSSHBytes round-trip")
    func sshBytesRoundTrip() throws {
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        var buffer = Data()
        SSHAgentWireFormat.appendSSHBytes(payload, to: &buffer)

        #expect(buffer.count == 8)

        var offset = buffer.startIndex
        let decoded = try SSHAgentWireFormat.readSSHBytes(from: buffer, at: &offset)
        #expect(decoded == payload)
    }

    @Test("readSSHBytes throws when length exceeds data")
    func sshBytesThrowsOnTruncatedData() {
        var buffer = Data()
        SSHAgentWireFormat.appendUInt32(100, to: &buffer)
        buffer.append(Data([0x01, 0x02]))
        var offset = buffer.startIndex

        #expect(throws: SSHAgentWireFormat.ParseError.self) {
            _ = try SSHAgentWireFormat.readSSHBytes(from: buffer, at: &offset)
        }
    }

    @Test("appendSSHString encodes UTF-8 string as SSH string")
    func sshStringEncoding() throws {
        var buffer = Data()
        SSHAgentWireFormat.appendSSHString("hello", to: &buffer)

        var offset = buffer.startIndex
        let length = try SSHAgentWireFormat.readUInt32(from: buffer, at: &offset)
        #expect(length == 5)
        let decoded = try SSHAgentWireFormat.readSSHBytes(from: buffer, at: &buffer.startIndex)
        #expect(String(data: decoded, encoding: .utf8) == "hello")
    }
}

// MARK: - Request parsing

@Suite("SSHAgentWireFormat request parsing")
struct SSHAgentRequestParsingTests {
    @Test("parseRequest identifies SSH_AGENTC_REQUEST_IDENTITIES")
    func parseRequestIdentities() throws {
        let data = Data([SSHAgentMessageType.requestIdentities.rawValue])
        let request = try SSHAgentWireFormat.parseRequest(from: data)

        guard case .requestIdentities = request else {
            Issue.record("Expected requestIdentities")
            return
        }
    }

    @Test("parseRequest parses SSH_AGENTC_SIGN_REQUEST")
    func parseSignRequest() throws {
        var payload = Data()
        payload.append(SSHAgentMessageType.signRequest.rawValue)

        let keyBlob = Data([0x01, 0x02, 0x03])
        SSHAgentWireFormat.appendSSHBytes(keyBlob, to: &payload)

        let signData = Data([0x04, 0x05])
        SSHAgentWireFormat.appendSSHBytes(signData, to: &payload)

        SSHAgentWireFormat.appendUInt32(0, to: &payload)

        let request = try SSHAgentWireFormat.parseRequest(from: payload)

        guard case .signRequest(let parsedBlob, let parsedData, let flags) = request else {
            Issue.record("Expected signRequest")
            return
        }
        #expect(parsedBlob == keyBlob)
        #expect(parsedData == signData)
        #expect(flags == 0)
    }

    @Test("parseRequest throws on empty data")
    func parseRequestThrowsOnEmpty() {
        #expect(throws: SSHAgentWireFormat.ParseError.self) {
            _ = try SSHAgentWireFormat.parseRequest(from: Data())
        }
    }

    @Test("parseRequest throws on unsupported message type")
    func parseRequestThrowsOnUnsupported() {
        #expect(throws: SSHAgentWireFormat.ParseError.self) {
            _ = try SSHAgentWireFormat.parseRequest(from: Data([0xFF]))
        }
    }
}

// MARK: - Response encoding

@Suite("SSHAgentWireFormat response encoding")
struct SSHAgentResponseEncodingTests {
    @Test("failure response is single byte")
    func failureResponse() {
        let encoded = SSHAgentWireFormat.encodeResponse(.failure)
        #expect(encoded == Data([SSHAgentMessageType.failure.rawValue]))
    }

    @Test("identitiesAnswer encodes identity count and entries")
    func identitiesAnswerEncoding() throws {
        let identity = SSHKeyIdentity(
            publicKeyBlob: Data([0xAA, 0xBB]),
            comment: "test-key"
        )
        let encoded = SSHAgentWireFormat.encodeResponse(.identitiesAnswer(identities: [identity]))

        var offset = encoded.startIndex
        let typeByte = encoded[offset]
        offset += 1
        #expect(typeByte == SSHAgentMessageType.identitiesAnswer.rawValue)

        let count = try SSHAgentWireFormat.readUInt32(from: encoded, at: &offset)
        #expect(count == 1)

        let blob = try SSHAgentWireFormat.readSSHBytes(from: encoded, at: &offset)
        #expect(blob == Data([0xAA, 0xBB]))

        let comment = try SSHAgentWireFormat.readSSHBytes(from: encoded, at: &offset)
        #expect(String(data: comment, encoding: .utf8) == "test-key")
    }

    @Test("signResponse wraps signature in SSH bytes")
    func signResponseEncoding() throws {
        let sig = Data([0x01, 0x02, 0x03])
        let encoded = SSHAgentWireFormat.encodeResponse(.signResponse(signature: sig))

        var offset = encoded.startIndex
        let typeByte = encoded[offset]
        offset += 1
        #expect(typeByte == SSHAgentMessageType.signResponse.rawValue)

        let decoded = try SSHAgentWireFormat.readSSHBytes(from: encoded, at: &offset)
        #expect(decoded == sig)
    }

    @Test("identitiesAnswer with zero keys has count zero")
    func emptyIdentitiesAnswer() throws {
        let encoded = SSHAgentWireFormat.encodeResponse(.identitiesAnswer(identities: []))

        var offset = encoded.startIndex
        offset += 1
        let count = try SSHAgentWireFormat.readUInt32(from: encoded, at: &offset)
        #expect(count == 0)
        #expect(offset == encoded.endIndex)
    }
}

// MARK: - Public key blob encoding

@Suite("SSHAgentWireFormat public key blob")
struct SSHAgentPublicKeyBlobTests {
    @Test("encodePublicKeyBlob produces valid SSH public key format")
    func encodePublicKeyBlobFormat() throws {
        let publicKey = Data([0x04, 0x01, 0x02, 0x03])
        let blob = SSHAgentWireFormat.encodePublicKeyBlob(
            algorithm: .ecdsaSHA2P256,
            publicKeyBytes: publicKey
        )

        var offset = blob.startIndex
        let algName = try SSHAgentWireFormat.readSSHBytes(from: blob, at: &offset)
        #expect(String(data: algName, encoding: .utf8) == "ecdsa-sha2-nistp256")

        let curveName = try SSHAgentWireFormat.readSSHBytes(from: blob, at: &offset)
        #expect(String(data: curveName, encoding: .utf8) == "nistp256")

        let keyData = try SSHAgentWireFormat.readSSHBytes(from: blob, at: &offset)
        #expect(keyData == publicKey)

        #expect(offset == blob.endIndex)
    }
}

// MARK: - SSHKeyMetadata

@Suite("SSHKeyMetadata")
struct SSHKeyMetadataTests {
    @Test("authorizedKeysEntry produces correct format")
    func authorizedKeysEntryFormat() {
        let publicKey = Data([0x04, 0x01, 0x02])
        let metadata = SSHKeyMetadata(
            id: UUID(),
            name: "test-key",
            keyType: .secureEnclaveP256,
            algorithm: .ecdsaSHA2P256,
            publicKeyData: publicKey,
            createdAt: Date()
        )

        let entry = metadata.authorizedKeysEntry
        #expect(entry.hasPrefix("ecdsa-sha2-nistp256 "))
        #expect(entry.hasSuffix(" test-key"))
    }
}
