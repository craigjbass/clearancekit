//
//  FilterInteractor.swift
//  opfilter
//

import Foundation
import os

// MARK: - FileOperation

enum FileOperation: String {
    case open     = "open"
    case rename   = "rename"
    case unlink   = "unlink"
    case link     = "link"
    case create   = "create"
    case truncate = "truncate"
    case copyfile      = "copyfile"
    case readdir       = "readdir"
    case exchangedata  = "exchangedata"
    case clone         = "clone"
}

// MARK: - FileAuthEvent

struct FileAuthEvent: Sendable {
    let correlationID: UUID
    let operation: FileOperation
    let path: String
    let processIdentity: ProcessIdentity
    let processID: pid_t
    let parentPID: pid_t
    let processPath: String
    let teamID: String
    let signingID: String
    let uid: uid_t
    let gid: gid_t
    let ttyPath: String?
    let deadline: UInt64
    let respond: @Sendable (_ allowed: Bool, _ cache: Bool) -> Void
}

// MARK: - MachTime

enum MachTime {
    /// How far before the ES deadline we stop waiting, in nanoseconds.
    static let safetyMarginNanoseconds: UInt64 = 100_000_000 // 100 ms

    /// Timebase ratio, computed once for the process lifetime.
    private static let timebase: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    /// Mach-unit equivalent of `safetyMarginNanoseconds`.
    static let safetyMarginMachUnits: UInt64 = {
        safetyMarginNanoseconds * UInt64(timebase.denom) / UInt64(timebase.numer)
    }()

    static func cutoff(for deadline: UInt64) -> UInt64 {
        guard deadline >= safetyMarginMachUnits else { return 0 }
        return deadline - safetyMarginMachUnits
    }

    static func nanoseconds(from start: UInt64, to end: UInt64) -> UInt64 {
        guard end >= start else { return 0 }
        return (end - start) * UInt64(timebase.numer) / UInt64(timebase.denom)
    }

    static func millisecondsToDeadline(_ deadline: UInt64) -> Int64 {
        let now = mach_absolute_time()
        guard deadline > now else { return 0 }
        let ticks = deadline - now
        let nanos = ticks * UInt64(timebase.numer) / UInt64(timebase.denom)
        return Int64(nanos / 1_000_000)
    }
}

// MARK: - WeakBox

final class WeakBox<T: AnyObject>: @unchecked Sendable {
    weak var value: T?
}

// MARK: - FilterInteractor

final class FilterInteractor: @unchecked Sendable {
    var onEvent: ((FolderOpenEvent) -> Void)?

    private let rulesStorage: OSAllocatedUnfairLock<[FAARule]>
    private let allowlistStorage: OSAllocatedUnfairLock<[AllowlistEntry]>
    private let ancestorAllowlistStorage: OSAllocatedUnfairLock<[AncestorAllowlistEntry]>
    private let jailRulesStorage: OSAllocatedUnfairLock<[JailRule]>
    private let processTree: ProcessTreeProtocol
    private let postRespondQueue: DispatchQueue
    private let auditLogger = AuditLogger()
    private let ttyNotifier = TTYNotifier()
    let pipeline: FileAuthPipeline

    init(
        initialRules: [FAARule] = faaPolicy,
        initialAllowlist: [AllowlistEntry] = baselineAllowlist,
        initialAncestorAllowlist: [AncestorAllowlistEntry] = [],
        initialJailRules: [JailRule] = [],
        processTree: ProcessTreeProtocol,
        pipeline: FileAuthPipeline,
        postRespondQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.post-respond", qos: .background)
    ) {
        self.rulesStorage = OSAllocatedUnfairLock(initialState: initialRules)
        self.allowlistStorage = OSAllocatedUnfairLock(initialState: initialAllowlist)
        self.ancestorAllowlistStorage = OSAllocatedUnfairLock(initialState: initialAncestorAllowlist)
        self.jailRulesStorage = OSAllocatedUnfairLock(initialState: initialJailRules)
        self.processTree = processTree
        self.pipeline = pipeline
        self.postRespondQueue = postRespondQueue
    }

    func currentRules() -> [FAARule] {
        rulesStorage.withLock { $0 }
    }

    func currentAllowlist() -> [AllowlistEntry] {
        allowlistStorage.withLock { $0 }
    }

    func currentAncestorAllowlist() -> [AncestorAllowlistEntry] {
        ancestorAllowlistStorage.withLock { $0 }
    }

    func updatePolicy(_ rules: [FAARule]) {
        rulesStorage.withLock { $0 = rules }
    }

    func updateAllowlist(_ entries: [AllowlistEntry]) {
        allowlistStorage.withLock { $0 = entries }
    }

    func updateAncestorAllowlist(_ entries: [AncestorAllowlistEntry]) {
        ancestorAllowlistStorage.withLock { $0 = entries }
    }

    func updateJailRules(_ rules: [JailRule]) {
        jailRulesStorage.withLock { $0 = rules }
    }

    // Called synchronously from the ESJailAdapter ES callback queue.
    // Jail policy is pure synchronous logic; responding inline avoids cooperative
    // thread saturation and deadline misses when the jail client receives the high
    // volume of events its inverted process muting generates. Post-respond work is
    // handed off to postRespondQueue immediately after respond() returns.
    //
    // jailRuleID is resolved by ESJailAdapter from its tracked muted-PID map,
    // covering both direct matches (signing ID matches rule) and inherited jails
    // (child of a jailed process). Providing the rule ID explicitly means this
    // path never needs to match by signing ID.
    func handleJailEventSync(_ fileEvent: FileAuthEvent, jailRuleID: UUID) {
        let allowlist = allowlistStorage.withLock { $0 }

        if isGloballyAllowed(allowlist: allowlist, processPath: fileEvent.processPath, signingID: fileEvent.signingID, teamID: fileEvent.teamID) {
            fileEvent.respond(true, true)
            return
        }

        let jailRules = jailRulesStorage.withLock { $0 }
        guard let rule = jailRules.first(where: { $0.id == jailRuleID }) else {
            fileEvent.respond(true, false)
            return
        }

        let decision = checkJailPath(rule: rule, path: fileEvent.path)
        fileEvent.respond(decision.isAllowed, false)

        let ancestors = processTree.ancestors(of: fileEvent.processIdentity)
        postRespond(fileEvent: fileEvent, decision: decision, ancestors: ancestors, dwellNanoseconds: 0)
    }

    func handleFork(child: ProcessRecord) {
        processTree.insert(child)
    }

    func handleExec(newImage: ProcessRecord) {
        processTree.insert(newImage)
    }

    func handleExit(identity: ProcessIdentity) {
        processTree.remove(identity: identity)
    }

    func handleFileAuth(_ fileEvent: FileAuthEvent) {
        pipeline.submit(fileEvent)
    }

    func postRespond(fileEvent: FileAuthEvent, decision: PolicyDecision, ancestors: [AncestorInfo], dwellNanoseconds: UInt64) {
        postRespondQueue.async { [self] in
            let allowed = decision.isAllowed

            auditLogger.log(decision, for: fileEvent, ancestors: ancestors, dwellNanoseconds: dwellNanoseconds, operationID: fileEvent.correlationID)

            if !allowed {
                ttyNotifier.writeDenial(path: fileEvent.path, reason: decision.reason, ttyPath: fileEvent.ttyPath)
            }

            let folderOpenEvent = FolderOpenEvent(
                operation: fileEvent.operation.rawValue,
                path: fileEvent.path,
                timestamp: Date(),
                processID: fileEvent.processID,
                processPath: fileEvent.processPath,
                teamID: fileEvent.teamID,
                signingID: fileEvent.signingID,
                accessAllowed: allowed,
                decisionReason: decision.reason,
                ancestors: ancestors,
                matchedRuleID: decision.matchedRuleID,
                jailedRuleID: decision.jailedRuleID,
                eventID: fileEvent.correlationID
            )
            onEvent?(folderOpenEvent)
        }
    }

}
