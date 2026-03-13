//
//  XPCProtocol.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation

// MARK: - Constants

public enum XPCConstants {
    public static let daemonServiceName = "uk.craigbass.clearancekit.daemon"
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

// MARK: - Daemon Service Protocol (exposed by the LaunchDaemon)
//
// Called by the GUI app:  registerClient / unregisterClient / isMonitoringActive /
//                          fetchRecentEvents / addRule / updateRule / removeRule / requestResync
// Called by opfilter:     registerFilterClient / reportEvent / reportMonitoringStatus

@objc(DaemonServiceProtocol)
public protocol DaemonServiceProtocol {
    // GUI registration
    func registerClient(withReply reply: @escaping (Bool) -> Void)
    func unregisterClient(withReply reply: @escaping (Bool) -> Void)
    func isMonitoringActive(withReply reply: @escaping (Bool) -> Void)
    func fetchRecentEvents(withReply reply: @escaping ([FolderOpenEvent]) -> Void)

    // opfilter registration
    func registerFilterClient(withReply reply: @escaping (Bool) -> Void)

    // User-rule mutations (GUI → daemon). Daemon stores, then broadcasts merged
    // policy to opfilter clients and updated user rules to all GUI clients.
    func addRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void)
    func updateRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void)
    func removeRule(_ ruleID: NSUUID, withReply reply: @escaping (Bool) -> Void)

    // Telemetry from opfilter
    func reportEvent(_ event: FolderOpenEvent)
    func reportMonitoringStatus(_ isActive: Bool)

    // GUI requests a full status resync. Daemon asks filter clients to re-report
    // monitoring status and pushes the current user-rule snapshot back to the caller.
    func requestResync(withReply reply: @escaping () -> Void)
}

// MARK: - Daemon Client Protocol (exported by the GUI app for daemon callbacks)

@objc(DaemonClientProtocol)
public protocol DaemonClientProtocol {
    func folderOpened(_ event: FolderOpenEvent)
    func monitoringStatusChanged(_ isActive: Bool)
    // Daemon pushes the authoritative user-rule snapshot whenever it changes,
    // and once on connect (via requestResync).
    func userRulesUpdated(_ rulesData: NSData)
}

// MARK: - Filter Client Protocol (exported by opfilter for daemon policy-push callbacks)

@objc(FilterClientProtocol)
public protocol FilterClientProtocol {
    func policyUpdated(_ policyData: NSData)
    func resyncStatus()
}

// MARK: - Any Client Protocol
//
// Combined protocol used as the daemon's remoteObjectInterface so it can call back
// to both GUI connections (DaemonClientProtocol) and opfilter connections
// (FilterClientProtocol) through a single interface declaration.

@objc(AnyClientProtocol)
public protocol AnyClientProtocol: DaemonClientProtocol, FilterClientProtocol {}
