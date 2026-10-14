//
//  QuietListTests.swift
//  clearancekitTests
//

import Testing
import Foundation

private func quietEntry(
    signingID: String = "",
    processPath: String = "",
    platformBinary: Bool = false,
    teamID: String = ""
) -> QuietListEntry {
    QuietListEntry(id: UUID(), signingID: signingID, processPath: processPath, platformBinary: platformBinary, teamID: teamID)
}

@Suite("notificationPolicy")
struct QuietListTests {
    @Test("signing ID and team match gives quiet")
    func signingIDMatchGivesQuiet() {
        let quietList = [quietEntry(signingID: "com.example.noisy", teamID: "TEAM123")]

        let policy = notificationPolicy(processPath: "/Applications/Noisy.app/Contents/MacOS/Noisy", signingID: "com.example.noisy", teamID: "TEAM123", quietList: quietList)

        #expect(policy == .quiet)
    }

    @Test("team mismatch gives notify")
    func teamMismatchGivesNotify() {
        let quietList = [quietEntry(signingID: "com.example.noisy", teamID: "TEAM123")]

        let policy = notificationPolicy(processPath: "/tmp/noisy", signingID: "com.example.noisy", teamID: "EVIL999", quietList: quietList)

        #expect(policy == .notify)
    }

    @Test("platform-binary entry matches only Apple platform binaries")
    func platformBinaryEntryMatchesOnlyApple() {
        let quietList = [quietEntry(signingID: "com.apple.noisy", platformBinary: true)]

        #expect(notificationPolicy(processPath: "/usr/libexec/noisy", signingID: "com.apple.noisy", teamID: appleTeamID, quietList: quietList) == .quiet)
        #expect(notificationPolicy(processPath: "/usr/libexec/noisy", signingID: "com.apple.noisy", teamID: "", quietList: quietList) == .notify)
        #expect(notificationPolicy(processPath: "/usr/libexec/noisy", signingID: "com.apple.noisy", teamID: "TEAM123", quietList: quietList) == .notify)
    }

    @Test("path entry matches the exact path")
    func pathEntryMatchesExactPath() {
        let quietList = [quietEntry(processPath: "/usr/local/bin/noisy")]

        let policy = notificationPolicy(processPath: "/usr/local/bin/noisy", signingID: "", teamID: "", quietList: quietList)

        #expect(policy == .quiet)
    }

    @Test("path entry does not prefix-match")
    func pathEntryDoesNotPrefixMatch() {
        let quietList = [quietEntry(processPath: "/usr/local/bin/noisy")]

        #expect(notificationPolicy(processPath: "/usr/local/bin/noisy-helper", signingID: "", teamID: "", quietList: quietList) == .notify)
        #expect(notificationPolicy(processPath: "/usr/local/bin/noisy/child", signingID: "", teamID: "", quietList: quietList) == .notify)
    }

    @Test("empty quiet list gives notify")
    func emptyQuietListGivesNotify() {
        let policy = notificationPolicy(processPath: "/usr/bin/anything", signingID: "com.example.anything", teamID: "TEAM123", quietList: [])

        #expect(policy == .notify)
    }

    @Test("baseline quiet list quiets each Spotlight indexer", arguments: spotlightIndexerSigningIDs)
    func baselineQuietsEachIndexer(signingID: String) {
        let policy = notificationPolicy(
            processPath: "/System/Library/Frameworks/CoreServices.framework/indexer",
            signingID: signingID,
            teamID: appleTeamID,
            quietList: baselineQuietList
        )

        #expect(policy == .quiet)
    }

    @Test("baseline quiet list does not quiet a third-party process with an indexer signing ID")
    func baselineDoesNotQuietThirdPartyIndexerID() {
        let policy = notificationPolicy(processPath: "/tmp/fake", signingID: "com.apple.mdworker_shared", teamID: "EVIL999", quietList: baselineQuietList)

        #expect(policy == .notify)
    }

    @Test("baseline quiet list IDs are stable")
    func baselineQuietListIDsAreStable() {
        #expect(baselineQuietList.map(\.id.uuidString) == [
            "D0000000-0000-0000-0000-000000000001",
            "D0000000-0000-0000-0000-000000000002",
            "D0000000-0000-0000-0000-000000000003",
            "D0000000-0000-0000-0000-000000000004",
        ])
        #expect(baselineQuietList.map(\.signingID) == spotlightIndexerSigningIDs)
        #expect(baselineQuietList.allSatisfy { $0.platformBinary })
    }
}

@Suite("QuietListEntry.quieting")
struct QuietListEntryQuietingTests {
    @Test("Apple platform binary is quieted by signing ID as a platform binary")
    func applePlatformBinaryIsQuietedBySigningID() {
        let entry = QuietListEntry.quieting(processPath: "/usr/libexec/noisy", signingID: "com.apple.noisy", teamID: appleTeamID)

        #expect(entry.signingID == "com.apple.noisy")
        #expect(entry.platformBinary)
        #expect(entry.teamID == "")
        #expect(entry.processPath == "")
    }

    @Test("third-party process is quieted by signing ID and team")
    func thirdPartyProcessIsQuietedBySigningIDAndTeam() {
        let entry = QuietListEntry.quieting(processPath: "/Applications/Noisy.app/Contents/MacOS/Noisy", signingID: "com.example.noisy", teamID: "TEAM123")

        #expect(entry.signingID == "com.example.noisy")
        #expect(entry.teamID == "TEAM123")
        #expect(!entry.platformBinary)
        #expect(entry.processPath == "")
    }

    @Test("process without a team is quieted by path")
    func processWithoutTeamIsQuietedByPath() {
        let entry = QuietListEntry.quieting(processPath: "/usr/local/bin/adhoc", signingID: "adhoc-chosen-id", teamID: "")

        #expect(entry.processPath == "/usr/local/bin/adhoc")
        #expect(entry.signingID == "")
        #expect(!entry.platformBinary)
        #expect(entry.teamID == "")
    }
}
