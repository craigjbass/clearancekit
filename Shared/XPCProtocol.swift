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
public class AncestorInfo: NSObject, NSSecureCoding, @unchecked Sendable {
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
    @objc public let operation: String
    @objc public let path: String
    @objc public let secondaryPath: String?
    @objc public let timestamp: Date
    @objc public let processID: Int32
    @objc public let processPath: String
    @objc public let teamID: String
    @objc public let signingID: String
    @objc public let accessAllowed: Bool
    @objc public let decisionReason: String
    @objc public let ancestors: [AncestorInfo]
    public let matchedRuleID: UUID?
    public let jailedRuleID: UUID?

    public init(
        operation: String = "open",
        path: String,
        secondaryPath: String? = nil,
        timestamp: Date,
        processID: Int32,
        processPath: String,
        teamID: String = "",
        signingID: String = "",
        accessAllowed: Bool = true,
        decisionReason: String = "",
        ancestors: [AncestorInfo] = [],
        matchedRuleID: UUID? = nil,
        jailedRuleID: UUID? = nil,
        eventID: UUID = UUID()
    ) {
        self.eventID = eventID
        self.operation = operation
        self.path = path
        self.secondaryPath = secondaryPath
        self.timestamp = timestamp
        self.processID = processID
        self.processPath = processPath
        self.teamID = teamID
        self.signingID = signingID
        self.accessAllowed = accessAllowed
        self.decisionReason = decisionReason
        self.ancestors = ancestors
        self.matchedRuleID = matchedRuleID
        self.jailedRuleID = jailedRuleID
        super.init()
    }

    public required init?(coder: NSCoder) {
        guard let path = coder.decodeObject(of: NSString.self, forKey: "path") as String?,
              let timestamp = coder.decodeObject(of: NSDate.self, forKey: "timestamp") as Date?,
              let processPath = coder.decodeObject(of: NSString.self, forKey: "processPath") as String? else {
            return nil
        }
        self.eventID = (coder.decodeObject(of: NSUUID.self, forKey: "eventID") as UUID?) ?? UUID()
        self.operation = (coder.decodeObject(of: NSString.self, forKey: "operation") as String?) ?? "open"
        self.path = path
        self.secondaryPath = coder.decodeObject(of: NSString.self, forKey: "secondaryPath") as String?
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
        self.jailedRuleID = coder.decodeObject(of: NSUUID.self, forKey: "jailedRuleID") as UUID?
        super.init()
    }

    public func encode(with coder: NSCoder) {
        coder.encode(eventID as NSUUID, forKey: "eventID")
        coder.encode(operation as NSString, forKey: "operation")
        coder.encode(path as NSString, forKey: "path")
        if let secondaryPath { coder.encode(secondaryPath as NSString, forKey: "secondaryPath") }
        coder.encode(timestamp as NSDate, forKey: "timestamp")
        coder.encode(processID, forKey: "processID")
        coder.encode(processPath as NSString, forKey: "processPath")
        coder.encode(teamID as NSString, forKey: "teamID")
        coder.encode(signingID as NSString, forKey: "signingID")
        coder.encode(accessAllowed, forKey: "accessAllowed")
        coder.encode(decisionReason as NSString, forKey: "decisionReason")
        coder.encode(ancestors as NSArray, forKey: "ancestors")
        if let matchedRuleID { coder.encode(matchedRuleID as NSUUID, forKey: "matchedRuleID") }
        if let jailedRuleID { coder.encode(jailedRuleID as NSUUID, forKey: "jailedRuleID") }
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
    @objc public let pidVersion: UInt32
    @objc public let parentPID: Int32
    @objc public let parentPIDVersion: UInt32
    @objc public let path: String
    @objc public let teamID: String
    @objc public let signingID: String
    @objc public let uid: UInt32
    @objc public let gid: UInt32

    public init(pid: Int32, pidVersion: UInt32, parentPID: Int32, parentPIDVersion: UInt32, path: String, teamID: String, signingID: String, uid: UInt32, gid: UInt32) {
        self.pid = pid
        self.pidVersion = pidVersion
        self.parentPID = parentPID
        self.parentPIDVersion = parentPIDVersion
        self.path = path
        self.teamID = teamID
        self.signingID = signingID
        self.uid = uid
        self.gid = gid
        super.init()
    }

    public required init?(coder: NSCoder) {
        guard let path = coder.decodeObject(of: NSString.self, forKey: "path") as String? else { return nil }
        self.pid = coder.decodeInt32(forKey: "pid")
        self.pidVersion = UInt32(bitPattern: coder.decodeInt32(forKey: "pidVersion"))
        self.parentPID = coder.decodeInt32(forKey: "parentPID")
        self.parentPIDVersion = UInt32(bitPattern: coder.decodeInt32(forKey: "parentPIDVersion"))
        self.path = path
        self.teamID = (coder.decodeObject(of: NSString.self, forKey: "teamID") as String?) ?? ""
        self.signingID = (coder.decodeObject(of: NSString.self, forKey: "signingID") as String?) ?? ""
        self.uid = UInt32(bitPattern: coder.decodeInt32(forKey: "uid"))
        self.gid = UInt32(bitPattern: coder.decodeInt32(forKey: "gid"))
        super.init()
    }

    public func encode(with coder: NSCoder) {
        coder.encode(pid, forKey: "pid")
        coder.encode(Int32(bitPattern: pidVersion), forKey: "pidVersion")
        coder.encode(parentPID, forKey: "parentPID")
        coder.encode(Int32(bitPattern: parentPIDVersion), forKey: "parentPIDVersion")
        coder.encode(path as NSString, forKey: "path")
        coder.encode(teamID as NSString, forKey: "teamID")
        coder.encode(signingID as NSString, forKey: "signingID")
        coder.encode(Int32(bitPattern: uid), forKey: "uid")
        coder.encode(Int32(bitPattern: gid), forKey: "gid")
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

// MARK: - TamperAttemptEvent

@objc(TamperAttemptEvent)
public class TamperAttemptEvent: NSObject, NSSecureCoding, @unchecked Sendable {
    public static var supportsSecureCoding: Bool { true }

    @objc public let eventID: UUID
    @objc public let timestamp: Date
    @objc public let sourcePID: Int32
    @objc public let sourcePIDVersion: UInt32
    @objc public let teamID: String
    @objc public let signingID: String
    /// "signal" or "proc_suspend_resume"
    @objc public let esEventType: String

    public init(
        sourcePID: Int32,
        sourcePIDVersion: UInt32,
        teamID: String,
        signingID: String,
        esEventType: String,
        timestamp: Date = Date(),
        eventID: UUID = UUID()
    ) {
        self.eventID = eventID
        self.timestamp = timestamp
        self.sourcePID = sourcePID
        self.sourcePIDVersion = sourcePIDVersion
        self.teamID = teamID
        self.signingID = signingID
        self.esEventType = esEventType
        super.init()
    }

    public required init?(coder: NSCoder) {
        guard let timestamp = coder.decodeObject(of: NSDate.self, forKey: "timestamp") as Date? else { return nil }
        self.eventID = (coder.decodeObject(of: NSUUID.self, forKey: "eventID") as UUID?) ?? UUID()
        self.timestamp = timestamp
        self.sourcePID = coder.decodeInt32(forKey: "sourcePID")
        self.sourcePIDVersion = UInt32(bitPattern: coder.decodeInt32(forKey: "sourcePIDVersion"))
        self.teamID = (coder.decodeObject(of: NSString.self, forKey: "teamID") as String?) ?? ""
        self.signingID = (coder.decodeObject(of: NSString.self, forKey: "signingID") as String?) ?? ""
        self.esEventType = (coder.decodeObject(of: NSString.self, forKey: "esEventType") as String?) ?? ""
        super.init()
    }

    public func encode(with coder: NSCoder) {
        coder.encode(eventID as NSUUID, forKey: "eventID")
        coder.encode(timestamp as NSDate, forKey: "timestamp")
        coder.encode(sourcePID, forKey: "sourcePID")
        coder.encode(Int32(bitPattern: sourcePIDVersion), forKey: "sourcePIDVersion")
        coder.encode(teamID as NSString, forKey: "teamID")
        coder.encode(signingID as NSString, forKey: "signingID")
        coder.encode(esEventType as NSString, forKey: "esEventType")
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

    // User ancestor-allowlist mutations (GUI → opfilter). Opfilter stores, then applies
    // the merged ancestor allowlist and pushes updates to all GUI clients.
    func addAncestorAllowlistEntry(_ entryData: NSData, withReply reply: @escaping (Bool) -> Void)
    func removeAncestorAllowlistEntry(_ entryID: NSUUID, withReply reply: @escaping (Bool) -> Void)

    // User jail-rule mutations (GUI → opfilter). Opfilter stores, then applies merged
    // jail rules directly and pushes updated user jail rules to all GUI clients.
    func addJailRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void)
    func updateJailRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void)
    func removeJailRule(_ ruleID: NSUUID, withReply reply: @escaping (Bool) -> Void)

    // GUI requests a full status resync. Opfilter pushes the current user-rule
    // and allowlist snapshots back to the caller.
    func requestResync(withReply reply: @escaping () -> Void)

    // Returns a snapshot of all running processes with code-signing information.
    func fetchProcessList(withReply reply: @escaping ([RunningProcessInfo]) -> Void)

    // Returns the subset of running processes currently tracked as jailed by the extension.
    func fetchActiveJailedProcesses(withReply reply: @escaping ([RunningProcessInfo]) -> Void)

    // Returns a snapshot of all ProcessRecord entries currently held in the extension's ProcessTree.
    func fetchProcessTree(withReply reply: @escaping ([RunningProcessInfo]) -> Void)

    // Discovery mode: temporarily monitor /Users so opfilter delivers events
    // for apps that have no policy rules yet. Call endDiscovery when done.
    func beginDiscovery(withReply reply: @escaping () -> Void)
    func endDiscovery(withReply reply: @escaping () -> Void)

    // Allow-event stream: the GUI subscribes when the events screen is
    // visible and unsubscribes when the screen leaves view or the window hides.
    func beginAllowEventStream(withReply reply: @escaping (Bool) -> Void)
    func endAllowEventStream(withReply reply: @escaping (Bool) -> Void)

    // Metrics-event stream: the GUI subscribes when the metrics screen is
    // visible and unsubscribes when it leaves view or the window hides.
    // Opfilter halts the 1Hz sampling timer when no client is subscribed.
    func beginMetricsEventStream(withReply reply: @escaping (Bool) -> Void)
    func endMetricsEventStream(withReply reply: @escaping (Bool) -> Void)

    // Database signature issue resolution. Called after the GUI presents the
    // issue to the user and obtains Touch ID authorisation. If approved is true,
    // opfilter re-signs the suspect data and loads it. If false, opfilter clears
    // all user rules and allowlist entries.
    func resolveSignatureIssue(approved: Bool, withReply reply: @escaping () -> Void)

    // Jail feature toggle. When enabled, opfilter creates the jail ES client;
    // when disabled, it tears it down. Default is disabled.
    func setJailEnabled(_ enabled: Bool, withReply reply: @escaping (Bool) -> Void)

    // MCP server toggle. Persisted in the feature_flags table with tamper-resistant
    // signature. On signature failure the flag defaults to disabled.
    func setMCPEnabled(_ enabled: Bool, withReply reply: @escaping (Bool) -> Void)

    // Returns a snapshot of recent tamper attempt events.
    func fetchRecentTamperEvents(withReply reply: @escaping ([TamperAttemptEvent]) -> Void)

    // Bundle updater signature mutations (GUI → opfilter). Opfilter stores, signs,
    // and pushes the updated list to all GUI clients.
    func saveBundleUpdaterSignatures(_ signaturesData: NSData, withReply reply: @escaping (Bool) -> Void)
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
    func managedAncestorAllowlistUpdated(_ allowlistData: NSData)
    func userAncestorAllowlistUpdated(_ allowlistData: NSData)
    func managedJailRulesUpdated(_ rulesData: NSData)
    func userJailRulesUpdated(_ rulesData: NSData)
    // Opfilter pushes the current jail-enabled state on connect and whenever it
    // changes. The GUI uses this to show/hide jail UI accordingly.
    func jailEnabledUpdated(_ enabled: Bool)
    // Opfilter pushes the current MCP-enabled feature flag on connect and whenever
    // it changes. The GUI starts or stops the MCP server accordingly.
    func mcpEnabledUpdated(_ enabled: Bool)
    // Opfilter calls this when it loads data that cannot be verified. The GUI
    // must present the issue to the user and call resolveSignatureIssue.
    func signatureIssueDetected(_ issue: SignatureIssueNotification)
    // Opfilter pushes a cumulative metrics snapshot once per second so the GUI
    // can compute per-second rates and render a live throughput graph.
    func metricsUpdated(_ snapshot: PipelineMetricsSnapshot)
    // Opfilter calls this when a tamper attempt against the opfilter process is denied.
    func tamperAttemptDenied(_ event: TamperAttemptEvent)
    // Opfilter pushes false when a client connects before initialisation completes,
    // and true once the initial policy snapshot has been delivered.
    func serviceReady(_ isReady: Bool)
    // Opfilter pushes the current bundle updater signatures on connect and
    // whenever the list changes.
    func bundleUpdaterSignaturesUpdated(_ signaturesData: NSData)
    /// Opfilter calls this to request a Touch ID authorization decision from
    /// the GUI. The GUI must respond with `true` (allow and open a session)
    /// or `false` (deny) within `remainingSeconds`, otherwise opfilter fails
    /// closed when the ES deadline elapses.
    func requestAuthorization(
        processName: String,
        signingID: String,
        teamID: String,
        pid: Int,
        pidVersion: UInt32,
        path: String,
        isWrite: Bool,
        remainingSeconds: Double,
        ancestors: [AncestorInfo],
        withReply reply: @escaping (Bool) -> Void
    )
}
