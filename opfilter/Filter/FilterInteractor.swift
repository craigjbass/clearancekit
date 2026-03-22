//
//  FilterInteractor.swift
//  opfilter
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "faa")

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
    let respond: @Sendable (Bool) -> Void
}

// MARK: - MachTime

private enum MachTime {
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
}

// MARK: - FilterEvent

enum FilterEvent {
    case fork(child: ProcessRecord)
    case exec(newImage: ProcessRecord)
    case exit(identity: ProcessIdentity)
    case fileAuth(FileAuthEvent)
}

// MARK: - FilterInteractor

final class FilterInteractor: @unchecked Sendable {
    var onEvent: ((FolderOpenEvent) -> Void)?

    private let rulesStorage: OSAllocatedUnfairLock<[FAARule]>
    private let allowlistStorage: OSAllocatedUnfairLock<[AllowlistEntry]>
    private let ancestorAllowlistStorage: OSAllocatedUnfairLock<[AncestorAllowlistEntry]>
    private let jailRulesStorage: OSAllocatedUnfairLock<[JailRule]>
    private let processTree: ProcessTreeProtocol
    private let auditLogger = AuditLogger()
    private let ttyNotifier = TTYNotifier()

    init(initialRules: [FAARule] = faaPolicy, initialAllowlist: [AllowlistEntry] = baselineAllowlist, initialAncestorAllowlist: [AncestorAllowlistEntry] = [], initialJailRules: [JailRule] = [], processTree: ProcessTreeProtocol = ProcessTree.shared) {
        self.rulesStorage = OSAllocatedUnfairLock(initialState: initialRules)
        self.allowlistStorage = OSAllocatedUnfairLock(initialState: initialAllowlist)
        self.ancestorAllowlistStorage = OSAllocatedUnfairLock(initialState: initialAncestorAllowlist)
        self.jailRulesStorage = OSAllocatedUnfairLock(initialState: initialJailRules)
        self.processTree = processTree
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
    // Jail policy is pure synchronous logic; responding inline avoids the async
    // Task dispatch that causes thread-pool saturation and deadline misses when
    // the jail client receives the high volume of events its inverted process
    // muting generates.
    //
    // jailRuleID is resolved by ESJailAdapter from its tracked muted-PID map,
    // covering both direct matches (signing ID matches rule) and inherited jails
    // (child of a jailed process). Providing the rule ID explicitly means this
    // path never needs to match by signing ID.
    func handleJailEventSync(_ fileEvent: FileAuthEvent, jailRuleID: UUID) {
        let allowlist = allowlistStorage.withLock { $0 }

        if isGloballyAllowed(allowlist: allowlist, processPath: fileEvent.processPath, signingID: fileEvent.signingID, teamID: fileEvent.teamID) {
            fileEvent.respond(true)
            return
        }

        let jailRules = jailRulesStorage.withLock { $0 }
        guard let rule = jailRules.first(where: { $0.id == jailRuleID }) else {
            // Stale mute: the jail rule was removed while this process was still muted.
            fileEvent.respond(true)
            return
        }

        let decision = checkJailPath(rule: rule, path: fileEvent.path)

        let allowed = decision.isAllowed
        fileEvent.respond(allowed)

        Task { [weak self] in
            guard let self else { return }
            let ancestors = processTree.ancestors(of: fileEvent.processIdentity)
            auditLogger.log(decision, for: fileEvent, ancestors: ancestors, dwellNanoseconds: 0)
            if !allowed {
                ttyNotifier.writeDenial(path: fileEvent.path, reason: decision.reason, ttyPath: fileEvent.ttyPath)
            }
            let folderEvent = FolderOpenEvent(
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
                jailedRuleID: decision.jailedRuleID
            )
            let callback = onEvent
            DispatchQueue.main.async { callback?(folderEvent) }
        }
    }

    func handle(_ event: FilterEvent) {
        switch event {
        case .fork(let child):
            let name = URL(fileURLWithPath: child.path).lastPathComponent
            logger.debug("FORK pid=\(child.identity.pid) pidversion=\(child.identity.pidVersion) process=\(name, privacy: .public)")
            processTree.insert(child)
        case .exec(let newImage):
            let name = URL(fileURLWithPath: newImage.path).lastPathComponent
            logger.debug("EXEC pid=\(newImage.identity.pid) pidversion=\(newImage.identity.pidVersion) process=\(name, privacy: .public)")
            processTree.insert(newImage)
        case .exit(let identity):
            logger.debug("EXIT pid=\(identity.pid) pidversion=\(identity.pidVersion)")
            processTree.remove(identity: identity)
        case .fileAuth(let fileEvent):
            let name = URL(fileURLWithPath: fileEvent.processPath).lastPathComponent
            logger.debug("FILEAUTH pid=\(fileEvent.processID) process=\(name, privacy: .public) op=\(fileEvent.operation.rawValue, privacy: .public) path=\(fileEvent.path, privacy: .public)")
            Task { await self.handleFileAuth(fileEvent) }
        }
    }

    private func handleFileAuth(_ fileEvent: FileAuthEvent) async {
        let name = URL(fileURLWithPath: fileEvent.processPath).lastPathComponent
        logger.debug("FILEAUTH-START pid=\(fileEvent.processID) process=\(name, privacy: .public) op=\(fileEvent.operation.rawValue, privacy: .public) path=\(fileEvent.path, privacy: .public)")

        let allowlist = allowlistStorage.withLock { $0 }
        let ancestorAllowlist = ancestorAllowlistStorage.withLock { $0 }

        // Fast path: globally allowlisted processes bypass all rule evaluation.
        if isGloballyAllowed(allowlist: allowlist, processPath: fileEvent.processPath, signingID: fileEvent.signingID, teamID: fileEvent.teamID) {
            logger.debug("FILEAUTH-ALLOW-GLOBAL pid=\(fileEvent.processID) process=\(name, privacy: .public)")
            fileEvent.respond(true)
            return
        }

        // Jail check: if the process itself or any ancestor matches a jail rule,
        // evaluate against the jail rule's allowed path prefixes. Runs after the
        // global allowlist (globally allowlisted processes escape jail) but before
        // FAA rule evaluation.
        let jailRules = jailRulesStorage.withLock { $0 }
        logger.debug("FILEAUTH-JAIL-CHECK pid=\(fileEvent.processID) process=\(name, privacy: .public) jailRuleCount=\(jailRules.count)")
        var jailDecision = checkJailPolicy(jailRules: jailRules, path: fileEvent.path, teamID: fileEvent.teamID, signingID: fileEvent.signingID)

        if jailDecision.jailedRuleID == nil, !jailRules.isEmpty {
            logger.debug("FILEAUTH-JAIL-ANCESTOR-CHECK pid=\(fileEvent.processID) process=\(name, privacy: .public)")
            let ancestors = processTree.ancestors(of: fileEvent.processIdentity)
            logger.debug("FILEAUTH-JAIL-ANCESTOR-FOUND pid=\(fileEvent.processID) process=\(name, privacy: .public) ancestorCount=\(ancestors.count)")
            if let ancestorDecision = checkAncestorJailPolicy(jailRules: jailRules, path: fileEvent.path, ancestors: ancestors) {
                jailDecision = ancestorDecision
            }
        }

        if jailDecision.jailedRuleID != nil {
            logger.debug("FILEAUTH-JAIL-MATCH pid=\(fileEvent.processID) process=\(name, privacy: .public) allowed=\(jailDecision.isAllowed)")
            let allowed = jailDecision.isAllowed
            fileEvent.respond(allowed)

            let logAncestors = processTree.ancestors(of: fileEvent.processIdentity)
            auditLogger.log(jailDecision, for: fileEvent, ancestors: logAncestors, dwellNanoseconds: 0)

            if !allowed {
                ttyNotifier.writeDenial(path: fileEvent.path, reason: jailDecision.reason, ttyPath: fileEvent.ttyPath)
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
                decisionReason: jailDecision.reason,
                ancestors: logAncestors,
                matchedRuleID: jailDecision.matchedRuleID,
                jailedRuleID: jailDecision.jailedRuleID
            )
            let callback = onEvent
            DispatchQueue.main.async {
                callback?(folderOpenEvent)
            }
            return
        }

        let rules = rulesStorage.withLock { $0 }
        let classification = classifyPath(fileEvent.path, rules: rules)
        logger.debug("FILEAUTH-FAA pid=\(fileEvent.processID) process=\(name, privacy: .public) classification=\(String(describing: classification), privacy: .public)")

        let decision: PolicyDecision
        var dwellNanoseconds: UInt64 = 0

        switch classification {
        case .noRuleApplies:
            // No rule covers this path — default allow. The ancestor allowlist only
            // needs to be checked when a policy rule could deny access; for paths
            // with no rules the access is allowed regardless of ancestry.
            decision = .noRuleApplies

        case .processLevelOnly where ancestorAllowlist.isEmpty:
            // Matching rule has only process-level criteria and the ancestor
            // allowlist is empty — evaluate immediately with no ancestry fetch.
            decision = await evaluateAccess(
                rules: rules, allowlist: allowlist, ancestorAllowlist: [],
                path: fileEvent.path,
                processPath: fileEvent.processPath,
                teamID: fileEvent.teamID,
                signingID: fileEvent.signingID
            )

        case .processLevelOnly, .ancestryRequired:
            // Either the ancestor allowlist is non-empty (so we must check ancestors
            // even for process-level rules) or the rule itself requires ancestry.
            // Pass a lazy provider so the potentially expensive process-tree wait is
            // deferred until a criterion actually requires it.
            let dwellStorage = OSAllocatedUnfairLock<UInt64>(initialState: 0)
            decision = await evaluateAccess(
                rules: rules, allowlist: allowlist, ancestorAllowlist: ancestorAllowlist,
                path: fileEvent.path,
                processPath: fileEvent.processPath,
                teamID: fileEvent.teamID,
                signingID: fileEvent.signingID,
                ancestryProvider: { [weak self, dwellStorage] in
                    guard let self else { return [] }
                    logger.debug("FILEAUTH-WAIT-START pid=\(fileEvent.processID) process=\(name, privacy: .public)")
                    let dwell = await self.waitForProcess(fileEvent.processIdentity, deadline: fileEvent.deadline)
                    dwellStorage.withLock { $0 = dwell }
                    logger.debug("FILEAUTH-WAIT-DONE pid=\(fileEvent.processID) process=\(name, privacy: .public) dwellMs=\(dwell / 1_000_000)")
                    return self.processTree.ancestors(of: fileEvent.processIdentity)
                }
            )
            dwellNanoseconds = dwellStorage.withLock { $0 }
        }

        let allowed = decision.isAllowed

        // Respond immediately — the ES deadline is strict and all work after
        // this point (logging, TTY output, XPC broadcast) is non-critical I/O.
        fileEvent.respond(allowed)

        // Best-efforts ancestry for logging — the tree may have been populated
        // since the decision was made, so re-query unconditionally.
        let logAncestors = processTree.ancestors(of: fileEvent.processIdentity)

        auditLogger.log(decision, for: fileEvent, ancestors: logAncestors, dwellNanoseconds: dwellNanoseconds)

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
            ancestors: logAncestors,
            matchedRuleID: decision.matchedRuleID
        )
        let callback = onEvent
        DispatchQueue.main.async {
            callback?(folderOpenEvent)
        }
    }

    private func waitForProcess(_ identity: ProcessIdentity, deadline: UInt64) async -> UInt64 {
        let start = mach_absolute_time()
        let cutoff = MachTime.cutoff(for: deadline)
        while mach_absolute_time() < cutoff {
            guard !processTree.contains(identity: identity) else { break }
            try? await Task.sleep(nanoseconds: 1_000_000) // 1 ms; frees the thread while waiting
        }
        return MachTime.nanoseconds(from: start, to: mach_absolute_time())
    }
}
