//
//  FolderOpenEventCodingTests.swift
//  clearancekitTests
//

import Testing
import Foundation

private let folderOpenEventClasses: [AnyClass] = [FolderOpenEvent.self, AncestorInfo.self, NSArray.self, NSDate.self, NSString.self, NSUUID.self]

@Suite("FolderOpenEvent secure coding")
struct FolderOpenEventCodingTests {
    @Test("quiet notification policy survives a secure-coding round trip")
    func quietPolicyRoundTrips() throws {
        let event = FolderOpenEvent(
            path: "/protected/file",
            timestamp: Date(timeIntervalSince1970: 1),
            processID: 42,
            processPath: "/usr/libexec/indexer",
            accessAllowed: false,
            notificationPolicy: .quiet
        )

        let archive = try NSKeyedArchiver.archivedData(withRootObject: event, requiringSecureCoding: true)
        let decoded = try NSKeyedUnarchiver.unarchivedObject(ofClasses: folderOpenEventClasses, from: archive) as? FolderOpenEvent

        #expect(decoded?.notificationPolicy == .quiet)
    }

    @Test("responsible process fields survive a secure-coding round trip")
    func responsibleProcessFieldsRoundTrip() throws {
        let event = FolderOpenEvent(
            path: "/protected/file",
            timestamp: Date(timeIntervalSince1970: 1),
            processID: 42,
            processPath: "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking",
            responsibleProcessPath: "/Applications/Safari.app/Contents/MacOS/Safari",
            responsibleSigningID: "com.apple.Safari",
            responsibleTeamID: "apple",
            notificationPolicy: .notify
        )

        let archive = try NSKeyedArchiver.archivedData(withRootObject: event, requiringSecureCoding: true)
        let decoded = try NSKeyedUnarchiver.unarchivedObject(ofClasses: folderOpenEventClasses, from: archive) as? FolderOpenEvent

        #expect(decoded?.responsibleProcessPath == "/Applications/Safari.app/Contents/MacOS/Safari")
        #expect(decoded?.responsibleSigningID == "com.apple.Safari")
        #expect(decoded?.responsibleTeamID == "apple")
    }

    @Test("event without responsible process fields decodes them as nil")
    func missingResponsibleProcessFieldsDecodeAsNil() throws {
        let event = FolderOpenEvent(
            path: "/protected/file",
            timestamp: Date(timeIntervalSince1970: 1),
            processID: 42,
            processPath: "/usr/libexec/indexer",
            notificationPolicy: .notify
        )

        let archive = try NSKeyedArchiver.archivedData(withRootObject: event, requiringSecureCoding: true)
        let decoded = try NSKeyedUnarchiver.unarchivedObject(ofClasses: folderOpenEventClasses, from: archive) as? FolderOpenEvent

        #expect(decoded?.path == "/protected/file")
        #expect(decoded?.responsibleProcessPath == nil)
        #expect(decoded?.responsibleSigningID == nil)
        #expect(decoded?.responsibleTeamID == nil)
    }

    @Test("payload without a notification policy decodes as notify")
    func missingPolicyDecodesAsNotify() throws {
        let decoded = try decodeLegacyEvent(notificationPolicyValue: nil)

        #expect(decoded?.path == "/protected/file")
        #expect(decoded?.notificationPolicy == .notify)
    }

    @Test("unknown notification policy value decodes as notify")
    func unknownPolicyDecodesAsNotify() throws {
        let decoded = try decodeLegacyEvent(notificationPolicyValue: 99)

        #expect(decoded?.path == "/protected/file")
        #expect(decoded?.notificationPolicy == .notify)
    }

    private func decodeLegacyEvent(notificationPolicyValue: Int?) throws -> FolderOpenEvent? {
        let archiver = NSKeyedArchiver(requiringSecureCoding: true)
        archiver.setClassName("FolderOpenEvent", for: HandBuiltFolderOpenEvent.self)
        archiver.encode(HandBuiltFolderOpenEvent(notificationPolicyValue: notificationPolicyValue), forKey: NSKeyedArchiveRootObjectKey)
        archiver.finishEncoding()
        return try NSKeyedUnarchiver.unarchivedObject(ofClasses: folderOpenEventClasses, from: archiver.encodedData) as? FolderOpenEvent
    }
}

@objc(HandBuiltFolderOpenEvent)
private final class HandBuiltFolderOpenEvent: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    private let notificationPolicyValue: Int?

    init(notificationPolicyValue: Int?) {
        self.notificationPolicyValue = notificationPolicyValue
        super.init()
    }

    required init?(coder: NSCoder) {
        return nil
    }

    func encode(with coder: NSCoder) {
        coder.encode("/protected/file" as NSString, forKey: "path")
        coder.encode(Date(timeIntervalSince1970: 1) as NSDate, forKey: "timestamp")
        coder.encode("/usr/libexec/indexer" as NSString, forKey: "processPath")
        coder.encode(false, forKey: "accessAllowed")
        if let notificationPolicyValue {
            coder.encode(notificationPolicyValue, forKey: "notificationPolicy")
        }
    }
}
