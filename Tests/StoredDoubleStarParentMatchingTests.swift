//
//  StoredDoubleStarParentMatchingTests.swift
//  clearancekitTests
//

import Testing

@Suite("storedDoubleStarParentMatching")
struct StoredDoubleStarParentMatchingTests {
    @Test("NULL column on a double-star pattern gives stopAtDoubleStar")
    func nullColumnOnDoubleStarPattern() {
        #expect(storedDoubleStarParentMatching(nil, pattern: "/a/**/secret") == .stopAtDoubleStar)
    }

    @Test("NULL column on a plain pattern gives allNestedDirectories")
    func nullColumnOnPlainPattern() {
        #expect(storedDoubleStarParentMatching(nil, pattern: "/a/secret") == .allNestedDirectories)
    }

    @Test("stored value wins over the implied value")
    func storedValueWinsOverImpliedValue() {
        #expect(storedDoubleStarParentMatching("all_nested_directories", pattern: "/a/**/secret") == .allNestedDirectories)
    }

    @Test("unknown stored value is rejected")
    func unknownStoredValueIsRejected() {
        #expect(storedDoubleStarParentMatching("sometimes", pattern: "/a/**/secret") == nil)
    }
}
