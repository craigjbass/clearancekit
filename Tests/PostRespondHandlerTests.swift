//
//  PostRespondHandlerTests.swift
//  clearancekitTests
//

import Testing
import Foundation

private final class EventCapture: @unchecked Sendable {
    var events: [FolderOpenEvent] = []
}

private func deniedDecision() -> PolicyDecision {
    .denied(ruleID: UUID(), ruleName: "/protected", ruleSource: .user, allowedCriteria: "", checkedProcess: .itself)
}

private func makeFileEvent(signingID: String, teamID: String) -> FileAuthEvent {
    FileAuthEvent(
        correlationID: UUID(),
        operation: .open,
        accessKind: .read,
        path: "/protected/file",
        secondaryPath: nil,
        movedEntryKind: .noDirectory,
        processIdentity: ProcessIdentity(pid: 100, pidVersion: 1),
        responsibleIdentity: ProcessIdentity(pid: 100, pidVersion: 1),
        processID: 100,
        parentPID: 1,
        parentPIDVersion: 0,
        processPath: "/usr/libexec/process",
        teamID: teamID,
        signingID: signingID,
        uid: 501,
        gid: 20,
        ttyPath: nil,
        deadline: 0,
        respond: { _, _ in }
    )
}

private func publishedEvent(
    signingID: String,
    teamID: String,
    decision: PolicyDecision,
    quietList: [QuietListEntry] = baselineQuietList
) -> FolderOpenEvent? {
    let queue = DispatchQueue(label: "test.post-respond")
    let handler = PostRespondHandler(quietListProvider: { quietList }, postRespondQueue: queue)
    let capture = EventCapture()
    handler.onEvent = { capture.events.append($0) }

    handler.postRespond(fileEvent: makeFileEvent(signingID: signingID, teamID: teamID), decision: decision, ancestors: [], dwellNanoseconds: 0)
    queue.sync {}

    return capture.events.first
}

@Suite("PostRespondHandler notification policy")
struct PostRespondHandlerTests {
    @Test("denied event from a baseline Spotlight indexer is quiet")
    func deniedIndexerEventIsQuiet() {
        let event = publishedEvent(signingID: "com.apple.mdworker_shared", teamID: appleTeamID, decision: deniedDecision())

        #expect(event?.notificationPolicy == .quiet)
    }

    @Test("denied event from another process notifies")
    func deniedOtherProcessEventNotifies() {
        let event = publishedEvent(signingID: "com.example.shell", teamID: "TEAM123", decision: deniedDecision())

        #expect(event?.notificationPolicy == .notify)
    }

    @Test("allowed event from a baseline Spotlight indexer notifies")
    func allowedIndexerEventNotifies() {
        let event = publishedEvent(signingID: "com.apple.mdworker_shared", teamID: appleTeamID, decision: .noRuleApplies)

        #expect(event?.notificationPolicy == .notify)
    }
}

private let safariFacts = ProcessFacts(
    processPath: "/Applications/Safari.app/Contents/MacOS/Safari",
    teamID: appleTeamID,
    signingID: "com.apple.Safari"
)

@Suite("PostRespondHandler responsible process")
struct PostRespondHandlerResponsibleProcessTests {
    @Test("decision that checked the responsible process sets the responsible fields")
    func responsibleDecisionSetsResponsibleFields() {
        let decision = PolicyDecision.denied(ruleID: UUID(), ruleName: "/protected", ruleSource: .user, allowedCriteria: "", checkedProcess: .responsible(safariFacts))

        let event = publishedEvent(signingID: "com.apple.WebKit.Networking", teamID: appleTeamID, decision: decision)

        #expect(event?.responsibleProcessPath == "/Applications/Safari.app/Contents/MacOS/Safari")
        #expect(event?.responsibleSigningID == "com.apple.Safari")
        #expect(event?.responsibleTeamID == appleTeamID)
    }

    @Test("decision that checked the process itself leaves the responsible fields nil")
    func itselfDecisionLeavesResponsibleFieldsNil() {
        let event = publishedEvent(signingID: "com.example.shell", teamID: "TEAM123", decision: deniedDecision())

        #expect(event?.responsibleProcessPath == nil)
        #expect(event?.responsibleSigningID == nil)
        #expect(event?.responsibleTeamID == nil)
    }

    @Test("decision with an unknown responsible process leaves the responsible fields nil")
    func unknownResponsibleDecisionLeavesResponsibleFieldsNil() {
        let decision = PolicyDecision.denied(ruleID: UUID(), ruleName: "/protected", ruleSource: .user, allowedCriteria: "", checkedProcess: .unknownResponsible)

        let event = publishedEvent(signingID: "com.apple.WebKit.Networking", teamID: appleTeamID, decision: decision)

        #expect(event?.responsibleProcessPath == nil)
    }

    @Test("denied event is quiet when the quiet list names the responsible process")
    func deniedEventQuietForResponsibleProcess() {
        let decision = PolicyDecision.denied(ruleID: UUID(), ruleName: "/protected", ruleSource: .user, allowedCriteria: "", checkedProcess: .responsible(safariFacts))
        let quietSafari = QuietListEntry(id: UUID(), signingID: "com.apple.Safari", processPath: "", platformBinary: true, teamID: "")

        let event = publishedEvent(signingID: "com.apple.WebKit.Networking", teamID: appleTeamID, decision: decision, quietList: [quietSafari])

        #expect(event?.notificationPolicy == .quiet)
    }
}
