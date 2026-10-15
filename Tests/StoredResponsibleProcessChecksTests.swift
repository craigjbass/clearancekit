//
//  StoredResponsibleProcessChecksTests.swift
//  clearancekitTests
//

import Testing
import Foundation

private let customChecks = [ProcessSignature(teamID: "TEAM1", signingID: "com.example.helper")]

private func canonicalJSON(_ rule: FAARule) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    return try encoder.encode([rule])
}

@Suite("storedResponsibleProcessChecks")
struct StoredResponsibleProcessChecksTests {
    @Test("NULL column gives the default list")
    func nullColumnGivesDefaultList() {
        #expect(storedResponsibleProcessChecks(nil) == defaultResponsibleProcessChecks)
    }

    @Test("default list is written as NULL")
    func defaultListIsWrittenAsNull() {
        #expect(columnTextForResponsibleProcessChecks(defaultResponsibleProcessChecks) == nil)
    }

    @Test("empty list round-trips as empty")
    func emptyListRoundTrips() {
        let columnText = columnTextForResponsibleProcessChecks([])

        #expect(columnText != nil)
        #expect(storedResponsibleProcessChecks(columnText) == [])
    }

    @Test("custom list round-trips")
    func customListRoundTrips() {
        let columnText = columnTextForResponsibleProcessChecks(customChecks)

        #expect(storedResponsibleProcessChecks(columnText) == customChecks)
    }

    @Test("a rule rebuilt from the stored column keeps its canonical JSON")
    func rebuiltRuleKeepsCanonicalJSON() throws {
        for checks in [[], customChecks, defaultResponsibleProcessChecks] {
            let rule = FAARule(protectedPathPrefix: "/a/secret", responsibleProcessChecks: checks)
            let restoredChecks = try #require(storedResponsibleProcessChecks(columnTextForResponsibleProcessChecks(checks)))
            let restored = FAARule(
                id: rule.id,
                protectedPathPrefix: rule.protectedPathPrefix,
                responsibleProcessChecks: restoredChecks
            )

            #expect(try canonicalJSON(restored) == canonicalJSON(rule))
        }
    }

    @Test("corrupt stored text is rejected")
    func corruptTextIsRejected() {
        #expect(storedResponsibleProcessChecks("not json") == nil)
    }
}
