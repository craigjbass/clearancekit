//
//  FilterInteractor.swift
//  opfilter
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "faa")

// MARK: - OpenFileEvent

struct OpenFileEvent {
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
    let respond: (Bool) -> Void
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
    case openFile(OpenFileEvent)
}

// MARK: - FilterInteractor

final class FilterInteractor {
    var onEvent: ((FolderOpenEvent) -> Void)?

    private let rulesStorage: OSAllocatedUnfairLock<[FAARule]>
    private let allowlistStorage: OSAllocatedUnfairLock<[AllowlistEntry]>

    /// AUTH_OPEN events are dispatched here so the ES callback thread stays
    /// free to deliver NOTIFY_EXEC / NOTIFY_FORK / NOTIFY_EXIT events.
    /// Without this, dwelling in waitForProcess would block the very events
    /// that populate the ProcessTree.
    private let authQueue = DispatchQueue(label: "uk.craigbass.clearancekit.auth-open", attributes: .concurrent)

    init(initialRules: [FAARule] = faaPolicy, initialAllowlist: [AllowlistEntry] = baselineAllowlist) {
        self.rulesStorage = OSAllocatedUnfairLock(initialState: initialRules)
        self.allowlistStorage = OSAllocatedUnfairLock(initialState: initialAllowlist)
    }

    func updatePolicy(_ rules: [FAARule]) {
        rulesStorage.withLock { $0 = rules }
    }

    func updateAllowlist(_ entries: [AllowlistEntry]) {
        allowlistStorage.withLock { $0 = entries }
    }

    func handle(_ event: FilterEvent) {
        switch event {
        case .fork(let child):
            let name = URL(fileURLWithPath: child.path).lastPathComponent
            logger.debug("FORK pid=\(child.identity.pid) pidversion=\(child.identity.pidVersion) process=\(name, privacy: .public)")
            ProcessTree.shared.insert(child)
        case .exec(let newImage):
            let name = URL(fileURLWithPath: newImage.path).lastPathComponent
            logger.debug("EXEC pid=\(newImage.identity.pid) pidversion=\(newImage.identity.pidVersion) process=\(name, privacy: .public)")
            ProcessTree.shared.insert(newImage)
        case .exit(let identity):
            logger.debug("EXIT pid=\(identity.pid) pidversion=\(identity.pidVersion)")
            ProcessTree.shared.remove(identity: identity)
        case .openFile(let fileEvent):
            authQueue.async { self.handleOpenFile(fileEvent) }
        }
    }

    private func handleOpenFile(_ fileEvent: OpenFileEvent) {
        let allowlist = allowlistStorage.withLock { $0 }

        // Fast path: globally allowlisted processes bypass all rule evaluation.
        if isGloballyAllowed(allowlist: allowlist, processPath: fileEvent.processPath, signingID: fileEvent.signingID, teamID: fileEvent.teamID) {
            fileEvent.respond(true)
            return
        }

        let rules = rulesStorage.withLock { $0 }
        let classification = classifyPath(fileEvent.path, rules: rules)

        let dwellNanoseconds: UInt64
        let ancestors: [AncestorInfo]
        let decision: PolicyDecision

        switch classification {
        case .noRuleApplies:
            dwellNanoseconds = 0
            ancestors = []
            decision = .noRuleApplies

        case .processLevelOnly:
            // Matching rule has only process-level criteria — evaluate
            // immediately using data from the AUTH_OPEN event.
            dwellNanoseconds = 0
            ancestors = []
            decision = checkFAAPolicy(
                rules: rules, path: fileEvent.path,
                processPath: fileEvent.processPath,
                teamID: fileEvent.teamID,
                signingID: fileEvent.signingID
            )

        case .ancestryRequired(let matchingRule):
            // Ancestry data is needed. Dwell until the process appears in
            // the tree, then look up ancestors for evaluation.
            dwellNanoseconds = waitForProcess(fileEvent.processIdentity, deadline: fileEvent.deadline)

            guard ProcessTree.shared.contains(identity: fileEvent.processIdentity) else {
                // Process never appeared before the deadline — fail safe.
                ancestors = []
                decision = .denied(
                    ruleID: matchingRule.id,
                    ruleName: matchingRule.protectedPathPrefix,
                    ruleSource: matchingRule.source,
                    allowedCriteria: "ancestry required but process not found in tree before deadline (pid=\(fileEvent.processIdentity.pid) pidversion=\(fileEvent.processIdentity.pidVersion))"
                )
                break
            }

            ancestors = ProcessTree.shared.ancestors(of: fileEvent.processIdentity)
            decision = checkFAAPolicy(
                rules: rules, path: fileEvent.path,
                processPath: fileEvent.processPath,
                teamID: fileEvent.teamID,
                signingID: fileEvent.signingID,
                ancestors: ancestors
            )
        }

        let allowed = decision.isAllowed

        // Respond immediately — the ES deadline is strict and all work after
        // this point (logging, TTY output, XPC broadcast) is non-critical I/O.
        fileEvent.respond(allowed)

        // Best-efforts ancestry for logging — the tree may have been populated
        // since the decision was made, so re-query unconditionally.
        let logAncestors = ProcessTree.shared.ancestors(of: fileEvent.processIdentity)

        logDecision(decision, for: fileEvent, ancestors: logAncestors, dwellNanoseconds: dwellNanoseconds)

        if !allowed {
            writeDenialToTTY(path: fileEvent.path, reason: decision.reason, ttyPath: fileEvent.ttyPath)
        }

        let folderOpenEvent = FolderOpenEvent(
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

    private func waitForProcess(_ identity: ProcessIdentity, deadline: UInt64) -> UInt64 {
        let start = mach_absolute_time()
        let cutoff = MachTime.cutoff(for: deadline)
        while mach_absolute_time() < cutoff {
            guard !ProcessTree.shared.contains(identity: identity) else { break }
            sched_yield()
        }
        return MachTime.nanoseconds(from: start, to: mach_absolute_time())
    }

    private func logDecision(_ decision: PolicyDecision, for fileEvent: OpenFileEvent, ancestors: [AncestorInfo], dwellNanoseconds: UInt64) {
        let operationID = UUID()
        let decisionTag = decision.isAllowed ? "ALLOW" : "DENIED"
        let processName = URL(fileURLWithPath: fileEvent.processPath).lastPathComponent
        let policyVersion = policyVersionString(for: decision)
        let userName = resolveUserName(uid: fileEvent.uid)
        let groupName = resolveGroupName(gid: fileEvent.gid)
        let ancestryTree = formatAncestryTree(ancestors)

        let line = [
            "action=FILE_ACCESS",
            "policy_version=\(policyVersion)",
            "policy_name=\(decision.policyName)",
            "path=\(fileEvent.path)",
            "access_type=open",
            "decision=\(decisionTag)",
            "operation_id=\(operationID.uuidString)",
            "pid=\(fileEvent.processID)",
            "ppid=\(fileEvent.parentPID)",
            "process=\(processName)",
            "processpath=\(fileEvent.processPath)",
            "uid=\(fileEvent.uid)",
            "user=\(userName)",
            "gid=\(fileEvent.gid)",
            "group=\(groupName)",
            "team_id=\(resolveTeamID(fileEvent.teamID))",
            "codesigning_id=\(fileEvent.signingID)",
            "ancestry_tree=\(ancestryTree)",
            "dwell_ns=\(dwellNanoseconds)",
        ].joined(separator: "|")

        logger.log("\(line, privacy: .public)")
    }

    private func policyVersionString(for decision: PolicyDecision) -> String {
        guard let source = decision.policySource else { return "" }
        switch source {
        case .builtin: return BuildInfo.gitHash
        case .user: return "user"
        case .mdm: return "mdm"
        }
    }

    private func formatAncestryTree(_ ancestors: [AncestorInfo]) -> String {
        guard !ancestors.isEmpty else { return "()" }
        let entries = ancestors.map { ancestor -> String in
            let user = resolveUserName(uid: ancestor.uid)
            return "user=\(user),signature=\(resolveTeamID(ancestor.teamID)):\(ancestor.signingID)"
        }
        return entries.map { "(\($0))" }.joined(separator: "->")
    }

    private func resolveTeamID(_ teamID: String) -> String {
        teamID.isEmpty ? appleTeamID : teamID
    }

    private func resolveUserName(uid: uid_t) -> String {
        guard let entry = getpwuid(uid) else { return "\(uid)" }
        return String(cString: entry.pointee.pw_name)
    }

    private func resolveGroupName(gid: gid_t) -> String {
        guard let entry = getgrgid(gid) else { return "\(gid)" }
        return String(cString: entry.pointee.gr_name)
    }

    private func writeDenialToTTY(path: String, reason: String, ttyPath: String?) {
        guard let ttyPath, let fh = FileHandle(forWritingAtPath: ttyPath) else { return }
        let msg = "\n[clearancekit] Access denied: \(path)\n  \(reason)\n"
        if let data = msg.data(using: .utf8) {
            fh.write(data)
        }
        let fd = fh.fileDescriptor
        let pgrp = tcgetpgrp(fd)
        if pgrp > 0 {
            killpg(pgrp, SIGWINCH)
        }
        fh.closeFile()
    }
}
