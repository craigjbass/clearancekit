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

    public init(path: String, teamID: String, signingID: String) {
        self.path = path
        self.teamID = teamID
        self.signingID = signingID
        super.init()
    }

    public required init?(coder: NSCoder) {
        guard let path = coder.decodeObject(of: NSString.self, forKey: "path") as String? else { return nil }
        self.path = path
        self.teamID = (coder.decodeObject(of: NSString.self, forKey: "teamID") as String?) ?? ""
        self.signingID = (coder.decodeObject(of: NSString.self, forKey: "signingID") as String?) ?? ""
        super.init()
    }

    public func encode(with coder: NSCoder) {
        coder.encode(path as NSString, forKey: "path")
        coder.encode(teamID as NSString, forKey: "teamID")
        coder.encode(signingID as NSString, forKey: "signingID")
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

// MARK: - Service Protocol (exposed by opfilter)
//
// Called by the GUI app:  registerClient / unregisterClient / isMonitoringActive /
//                          fetchRecentEvents / addRule / updateRule / removeRule / requestResync

@objc(ServiceProtocol)
public protocol ServiceProtocol {
    // GUI registration
    func registerClient(withReply reply: @escaping (Bool) -> Void)
    func unregisterClient(withReply reply: @escaping (Bool) -> Void)
    func isMonitoringActive(withReply reply: @escaping (Bool) -> Void)
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
}

// MARK: - Client Protocol (exported by the GUI app for opfilter callbacks)

@objc(ClientProtocol)
public protocol ClientProtocol {
    func folderOpened(_ event: FolderOpenEvent)
    func monitoringStatusChanged(_ isActive: Bool)
    // Opfilter pushes the authoritative rule snapshots on connect (via requestResync)
    // and whenever the respective tier changes.
    func managedRulesUpdated(_ rulesData: NSData)
    func userRulesUpdated(_ rulesData: NSData)
    func managedAllowlistUpdated(_ allowlistData: NSData)
    func userAllowlistUpdated(_ allowlistData: NSData)
}
