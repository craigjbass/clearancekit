//
//  EventProcessTargetTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("EventProcessTarget")
struct EventProcessTargetTests {

    private func makeEvent(
        responsibleProcessPath: String? = nil,
        responsibleSigningID: String? = nil,
        responsibleTeamID: String? = nil
    ) -> FolderOpenEvent {
        FolderOpenEvent(
            path: "/test",
            timestamp: Date(),
            processID: 1,
            processPath: "/System/Library/Frameworks/WebKit.framework/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking",
            teamID: "",
            signingID: "com.apple.WebKit.Networking",
            accessAllowed: false,
            responsibleProcessPath: responsibleProcessPath,
            responsibleSigningID: responsibleSigningID,
            responsibleTeamID: responsibleTeamID,
            notificationPolicy: .notify
        )
    }

    @Test("the process itself is the target when no responsible process is set")
    func processItselfIsTheTarget() {
        let target = EventProcessTarget(event: makeEvent())

        #expect(target.processPath.hasSuffix("com.apple.WebKit.Networking"))
        #expect(target.signingID == "com.apple.WebKit.Networking")
        #expect(target.teamID == "")
        #expect(target.viaSigningID == nil)
    }

    @Test("the responsible process is the target when it is set")
    func responsibleProcessIsTheTarget() {
        let target = EventProcessTarget(event: makeEvent(
            responsibleProcessPath: "/Applications/Safari.app/Contents/MacOS/Safari",
            responsibleSigningID: "com.apple.Safari",
            responsibleTeamID: ""
        ))

        #expect(target.processPath == "/Applications/Safari.app/Contents/MacOS/Safari")
        #expect(target.signingID == "com.apple.Safari")
        #expect(target.teamID == "")
        #expect(target.viaSigningID == "com.apple.WebKit.Networking")
    }

    @Test("a nil responsible signing ID and team ID become empty strings")
    func missingResponsibleIdentityBecomesEmpty() {
        let target = EventProcessTarget(event: makeEvent(responsibleProcessPath: "/tmp/poc"))

        #expect(target.processPath == "/tmp/poc")
        #expect(target.signingID == "")
        #expect(target.teamID == "")
    }
}
