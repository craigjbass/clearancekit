//
//  XPCProtocol.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation

// MARK: - Constants

public enum XPCConstants {
    public static let serviceName = "uk.craigbass.clearancekit.opfilter"
    public static let protocolVersion = "2.0"
    public static let teamID = "37KMK6XFTT"
    public static let bundleIDPrefix = "uk.craigbass.clearancekit"
}

// MARK: - AncestorInfo

@objc(AncestorInfo)
public class AncestorInfo: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    @objc public let path: String
    @objc public let teamID: String
    @objc public let signingID: String
    @objc public let uid: UInt32
    @objc public let gid: UInt32

    public init(path: String, teamID: String, signingID: String, uid: UInt32 = 0, gid: UInt32 = 0) {
        self.path = path
        self.teamID = teamID
        self.signingID = signingID
        self.uid = uid
        self.gid = gid
        super.init()
    }

    public required init?(coder: NSCoder) {
        guard let path = coder.decodeObject(of: NSString.self, forKey: "path") as String? else { return nil }
        self.path = path
        self.teamID = (coder.decodeObject(of: NSString.self, forKey: "teamID") as String?) ?? ""
        self.signingID = (coder.decodeObject(of: NSString.self, forKey: "signingID") as String?) ?? ""
        self.uid = UInt32(bitPattern: coder.decodeInt32(forKey: "uid"))
        self.gid = UInt32(bitPattern: coder.decodeInt32(forKey: "gid"))
        super.init()
    }

    public func encode(with coder: NSCoder) {
        coder.encode(path as NSString, forKey: "path")
        coder.encode(teamID as NSString, forKey: "teamID")
        coder.encode(signingID as NSString, forKey: "signingID")
        coder.encode(Int32(bitPattern: uid), forKey: "uid")
        coder.encode(Int32(bitPattern: gid), forKey: "gid")
    }
}

// MARK: - FolderOpenEvent

@objc(FolderOpenEvent)
public class FolderOpenEvent: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    @objc public let eventID: UUID
    @objc public let path: String
    @objc public let timestamp: Date
    @objc public let processID: Int32
    @objc public let processPath: String
    @objc public let teamID: String
    @objc public let signingID: String
    @objc public let accessAllowed: Bool
    @objc public let decisionReason: String
    @objc public let ancestors: [AncestorInfo]
    public let matchedRuleID: UUID?

    public init(
        path: String,
        timestamp: Date,
        processID: Int32,
        processPath: String,
        teamID: String = "",
        signingID: String = "",
        accessAllowed: Bool = true,
        decisionReason: String = "",
        ancestors: [AncestorInfo] = [],
        matchedRuleID: UUID? = nil,
        eventID: UUID = UUID()
    ) {
        self.eventID = eventID
        self.path = path
        self.timestamp = timestamp
        self.processID = processID
        self.processPath = processPath
        self.teamID = teamID
        self.signingID = signingID
        self.accessAllowed = accessAllowed
        self.decisionReason = decisionReason
        self.ancestors = ancestors
        self.matchedRuleID = matchedRuleID
        super.init()
    }

    public required init?(coder: NSCoder) {
        guard let path = coder.decodeObject(of: NSString.self, forKey: "path") as String?,
              let timestamp = coder.decodeObject(of: NSDate.self, forKey: "timestamp") as Date?,
              let processPath = coder.decodeObject(of: NSString.self, forKey: "processPath") as String? else {
            return nil
        }
        self.eventID = (coder.decodeObject(of: NSUUID.self, forKey: "eventID") as UUID?) ?? UUID()
        self.path = path
        self.timestamp = timestamp
        self.processID = coder.decodeInt32(forKey: "processID")
        self.processPath = processPath
        self.teamID = (coder.decodeObject(of: NSString.self, forKey: "teamID") as String?) ?? ""
        self.signingID = (coder.decodeObject(of: NSString.self, forKey: "signingID") as String?) ?? ""
        self.accessAllowed = coder.decodeBool(forKey: "accessAllowed")
        self.decisionReason = (coder.decodeObject(of: NSString.self, forKey: "decisionReason") as String?) ?? ""
        let decoded = coder.decodeObject(of: [NSArray.self, AncestorInfo.self], forKey: "ancestors") as? NSArray
        self.ancestors = decoded?.compactMap { $0 as? AncestorInfo } ?? []
        self.matchedRuleID = coder.decodeObject(of: NSUUID.self, forKey: "matchedRuleID") as UUID?
        super.init()
    }

    public func encode(with coder: NSCoder) {
        coder.encode(eventID as NSUUID, forKey: "eventID")
        coder.encode(path as NSString, forKey: "path")
        coder.encode(timestamp as NSDate, forKey: "timestamp")
        coder.encode(processID, forKey: "processID")
        coder.encode(processPath as NSString, forKey: "processPath")
        coder.encode(teamID as NSString, forKey: "teamID")
        coder.encode(signingID as NSString, forKey: "signingID")
        coder.encode(accessAllowed, forKey: "accessAllowed")
        coder.encode(decisionReason as NSString, forKey: "decisionReason")
        coder.encode(ancestors as NSArray, forKey: "ancestors")
        if let matchedRuleID { coder.encode(matchedRuleID as NSUUID, forKey: "matchedRuleID") }
    }

    public override var description: String {
        "FolderOpenEvent(path: \(path), pid: \(processID), processPath: \(processPath), teamID: \(teamID), signingID: \(signingID), allowed: \(accessAllowed), reason: \(decisionReason))"
    }
}

// MARK: - RunningProcessInfo

@objc(RunningProcessInfo)
public class RunningProcessInfo: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    @objc public let pid: Int32
    @objc public let parentPID: Int32
    @objc public let path: String
    @objc public let teamID: String
    @objc public let signingID: String
    @objc public let uid: UInt32

    public init(pid: Int32, parentPID: Int32, path: String, teamID: String, signingID: String, uid: UInt32) {
        self.pid = pid
        self.parentPID = parentPID
        self.path = path
        self.teamID = teamID
        self.signingID = signingID
        self.uid = uid
        super.init()
    }

    public required init?(coder: NSCoder) {
        guard let path = coder.decodeObject(of: NSString.self, forKey: "path") as String? else { return nil }
        self.pid = coder.decodeInt32(forKey: "pid")
        self.parentPID = coder.decodeInt32(forKey: "parentPID")
        self.path = path
        self.teamID = (coder.decodeObject(of: NSString.self, forKey: "teamID") as String?) ?? ""
        self.signingID = (coder.decodeObject(of: NSString.self, forKey: "signingID") as String?) ?? ""
        self.uid = UInt32(bitPattern: coder.decodeInt32(forKey: "uid"))
        super.init()
    }

    public func encode(with coder: NSCoder) {
        coder.encode(pid, forKey: "pid")
        coder.encode(parentPID, forKey: "parentPID")
        coder.encode(path as NSString, forKey: "path")
        coder.encode(teamID as NSString, forKey: "teamID")
        coder.encode(signingID as NSString, forKey: "signingID")
        coder.encode(Int32(bitPattern: uid), forKey: "uid")
    }
}

// MARK: - SignatureIssueNotification

@objc(SignatureIssueNotification)
public class SignatureIssueNotification: NSObject, NSSecureCoding {
    public static var supportsSecureCoding: Bool { true }

    @objc public let suspectRulesData: NSData?
    @objc public let suspectAllowlistData: NSData?

    public init(suspectRulesData: NSData?, suspectAllowlistData: NSData?) {
        self.suspectRulesData = suspectRulesData
        self.suspectAllowlistData = suspectAllowlistData
        super.init()
    }

    public required init?(coder: NSCoder) {
        self.suspectRulesData = coder.decodeObject(of: NSData.self, forKey: "suspectRulesData")
        self.suspectAllowlistData = coder.decodeObject(of: NSData.self, forKey: "suspectAllowlistData")
        super.init()
    }

    public func encode(with coder: NSCoder) {
        coder.encode(suspectRulesData, forKey: "suspectRulesData")
        coder.encode(suspectAllowlistData, forKey: "suspectAllowlistData")
    }
}

// MARK: - Service Protocol (exposed by opfilter)
//
// Called by the GUI app:  registerClient / unregisterClient /
//                          fetchRecentEvents / addRule / updateRule / removeRule / requestResync

@objc(ServiceProtocol)
public protocol ServiceProtocol {
    // GUI registration
    func registerClient(withReply reply: @escaping (Bool) -> Void)
    func unregisterClient(withReply reply: @escaping (Bool) -> Void)
    func fetchRecentEvents(withReply reply: @escaping ([FolderOpenEvent]) -> Void)

    // Version query — GUI asks for opfilter build version to detect stale components.
    func fetchVersionInfo(withReply reply: @escaping (_ serviceVersion: NSString) -> Void)

    // User-rule mutations (GUI → opfilter). Opfilter stores, then applies merged
    // policy directly and pushes updated user rules to all GUI clients.
    func addRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void)
    func updateRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void)
    func removeRule(_ ruleID: NSUUID, withReply reply: @escaping (Bool) -> Void)

    // User allowlist mutations (GUI → opfilter). Opfilter stores, then applies merged
    // allowlist directly and pushes updated user entries to all GUI clients.
    func addAllowlistEntry(_ entryData: NSData, withReply reply: @escaping (Bool) -> Void)
    func removeAllowlistEntry(_ entryID: NSUUID, withReply reply: @escaping (Bool) -> Void)

    // GUI requests a full status resync. Opfilter pushes the current user-rule
    // and allowlist snapshots back to the caller.
    func requestResync(withReply reply: @escaping () -> Void)

    // Returns a snapshot of all running processes with code-signing information.
    func fetchProcessList(withReply reply: @escaping ([RunningProcessInfo]) -> Void)

    // Discovery mode: temporarily monitor /Users so opfilter delivers events
    // for apps that have no policy rules yet. Call endDiscovery when done.
    func beginDiscovery(withReply reply: @escaping () -> Void)
    func endDiscovery(withReply reply: @escaping () -> Void)

    // Database signature issue resolution. Called after the GUI presents the
    // issue to the user and obtains Touch ID authorisation. If approved is true,
    // opfilter re-signs the suspect data and loads it. If false, opfilter clears
    // all user rules and allowlist entries.
    func resolveSignatureIssue(approved: Bool, withReply reply: @escaping () -> Void)
}

// MARK: - Client Protocol (exported by the GUI app for opfilter callbacks)

@objc(ClientProtocol)
public protocol ClientProtocol {
    func folderOpened(_ event: FolderOpenEvent)
    // Opfilter pushes the authoritative rule snapshots on connect (via requestResync)
    // and whenever the respective tier changes.
    func managedRulesUpdated(_ rulesData: NSData)
    func userRulesUpdated(_ rulesData: NSData)
    func managedAllowlistUpdated(_ allowlistData: NSData)
    func userAllowlistUpdated(_ allowlistData: NSData)
    // Opfilter calls this when it loads data that cannot be verified. The GUI
    // must present the issue to the user and call resolveSignatureIssue.
    func signatureIssueDetected(_ issue: SignatureIssueNotification)
}
