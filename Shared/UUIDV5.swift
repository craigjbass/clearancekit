//
//  UUIDV5.swift
//  clearancekit
//
//  UUID v5 (RFC 4122, SHA-1) derivation shared by ManagedPolicyLoader and
//  ManagedAllowlistLoader.
//

import Foundation
import CommonCrypto

/// RFC 4122 URL namespace UUID: 6ba7b811-9dad-11d1-80b4-00c04fd430c8
let uuidV5URLNamespace = UUID(uuidString: "6BA7B811-9DAD-11D1-80B4-00C04FD430C8")!

/// Derives a stable UUID v5 (RFC 4122, SHA-1) from a namespace UUID and a name string.
/// The name is encoded as UTF-8 before hashing.
func uuidV5(namespace: UUID, name: String) -> UUID {
    var nsBytes = namespace.uuid
    let nameBytes = Array(name.utf8)

    var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    var ctx = CC_SHA1_CTX()
    CC_SHA1_Init(&ctx)
    withUnsafeBytes(of: &nsBytes) { ptr in
        _ = CC_SHA1_Update(&ctx, ptr.baseAddress, CC_LONG(ptr.count))
    }
    CC_SHA1_Update(&ctx, nameBytes, CC_LONG(nameBytes.count))
    CC_SHA1_Final(&digest, &ctx)

    // Set version field to 5 (upper nibble 0x50) and RFC 4122 variant bits (10xxxxxx).
    digest[6] = (digest[6] & 0x0F) | 0x50
    digest[8] = (digest[8] & 0x3F) | 0x80

    return UUID(uuid: (
        digest[0],  digest[1],  digest[2],  digest[3],
        digest[4],  digest[5],  digest[6],  digest[7],
        digest[8],  digest[9],  digest[10], digest[11],
        digest[12], digest[13], digest[14], digest[15]
    ))
}

/// Parses an array of `"teamID:signingID"` strings into `ProcessSignature` values.
/// Entries that do not contain a colon are silently dropped.
func parseSignatures(_ strings: [String]) -> [ProcessSignature] {
    strings.compactMap { s in
        guard let colonIndex = s.firstIndex(of: ":") else { return nil }
        return ProcessSignature(
            teamID: String(s[s.startIndex..<colonIndex]),
            signingID: String(s[s.index(after: colonIndex)...])
        )
    }
}
