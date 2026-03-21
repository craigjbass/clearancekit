//
//  UUIDV5Tests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("uuidV5")
struct UUIDV5Tests {
    private let urlNamespace = UUID(uuidString: "6BA7B811-9DAD-11D1-80B4-00C04FD430C8")!

    @Test("produces the expected RFC 4122 v5 UUID for a known name")
    func knownVector() {
        // Python: uuid.uuid5(uuid.NAMESPACE_URL, "www.example.com")
        let expected = UUID(uuidString: "B63CDFA4-3DF9-568E-97AE-006C5B8FD652")!
        #expect(uuidV5(namespace: urlNamespace, name: "www.example.com") == expected)
    }

    @Test("version nibble is 5")
    func versionBits() {
        let result = uuidV5(namespace: urlNamespace, name: "test")
        let versionNibble = result.uuid.6 >> 4
        #expect(versionNibble == 5)
    }

    @Test("variant bits are RFC 4122 compliant")
    func variantBits() {
        let result = uuidV5(namespace: urlNamespace, name: "test")
        let variantBits = result.uuid.8 >> 6
        #expect(variantBits == 2)
    }

    @Test("is deterministic — same input yields same UUID")
    func deterministic() {
        let a = uuidV5(namespace: urlNamespace, name: "/Library/App/clearancekit")
        let b = uuidV5(namespace: urlNamespace, name: "/Library/App/clearancekit")
        #expect(a == b)
    }

    @Test("different names yield different UUIDs")
    func differentNamesProduceDifferentUUIDs() {
        let a = uuidV5(namespace: urlNamespace, name: "/path/one")
        let b = uuidV5(namespace: urlNamespace, name: "/path/two")
        #expect(a != b)
    }

    @Test("empty name is handled without crashing")
    func emptyName() {
        let result = uuidV5(namespace: urlNamespace, name: "")
        // Just verify version and variant bits are still set correctly.
        #expect(result.uuid.6 >> 4 == 5)
        #expect(result.uuid.8 >> 6 == 2)
    }
}

@Suite("parseSignatures")
struct ParseSignaturesTests {
    @Test("parses valid teamID:signingID strings")
    func parsesValidEntries() {
        let result = parseSignatures(["apple:com.apple.Safari", "37KMK6XFTT:*"])
        #expect(result == [
            ProcessSignature(teamID: "apple",      signingID: "com.apple.Safari"),
            ProcessSignature(teamID: "37KMK6XFTT", signingID: "*"),
        ])
    }

    @Test("drops entries without a colon")
    func dropsEntriesWithoutColon() {
        let result = parseSignatures(["no-colon-here"])
        #expect(result.isEmpty)
    }

    @Test("handles empty teamID or signingID")
    func handlesEmptyComponents() {
        let result = parseSignatures([":signingOnly", "teamOnly:"])
        #expect(result == [
            ProcessSignature(teamID: "",         signingID: "signingOnly"),
            ProcessSignature(teamID: "teamOnly", signingID: ""),
        ])
    }

    @Test("returns empty array for empty input")
    func emptyInput() {
        #expect(parseSignatures([]).isEmpty)
    }

    @Test("uses only the first colon as the delimiter")
    func firstColonDelimiter() {
        let result = parseSignatures(["team:signing:extra"])
        #expect(result == [ProcessSignature(teamID: "team", signingID: "signing:extra")])
    }
}
