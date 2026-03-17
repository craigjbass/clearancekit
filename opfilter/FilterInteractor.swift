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
    let processID: pid_t
    let parentPID: pid_t
    let processPath: String
    let teamID: String
    let signingID: String
    let uid: uid_t
    let gid: gid_t
    let ttyPath: String?
    let respond: (Bool) -> Void
}

// MARK: - FilterEvent

enum FilterEvent {
    case fork(child: ProcessRecord)
    case exec(newImage: ProcessRecord)
    case exit(pid: pid_t)
    case openFile(OpenFileEvent)
}

// MARK: - FilterInteractor

final class FilterInteractor {
    var onEvent: ((FolderOpenEvent) -> Void)?

    private let rulesStorage: OSAllocatedUnfairLock<[FAARule]>
    private let allowlistStorage: OSAllocatedUnfairLock<[AllowlistEntry]>

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
            ProcessTree.shared.insert(child)
        case .exec(let newImage):
            ProcessTree.shared.insert(newImage)
        case .exit(let pid):
            ProcessTree.shared.remove(pid: pid)
        case .openFile(let fileEvent):
            handleOpenFile(fileEvent)
        }
    }

    private func handleOpenFile(_ fileEvent: OpenFileEvent) {
        let allowlist = allowlistStorage.withLock { $0 }
        let rules = rulesStorage.withLock { $0 }
        let ancestors = ProcessTree.shared.ancestors(ofPID: fileEvent.processID)
        let decision = evaluateAccess(
            rules: rules,
            allowlist: allowlist,
            path: fileEvent.path,
            processPath: fileEvent.processPath,
            teamID: fileEvent.teamID,
            signingID: fileEvent.signingID,
            ancestors: ancestors
        )

        if case .globallyAllowed = decision {
            fileEvent.respond(true)
            return
        }

        let allowed = decision.isAllowed

        // Respond immediately — the ES deadline is strict and all work after
        // this point (logging, TTY output, XPC broadcast) is non-critical I/O.
        fileEvent.respond(allowed)

        logDecision(decision, for: fileEvent, ancestors: ancestors)

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
            ancestors: ancestors,
            matchedRuleID: decision.matchedRuleID
        )
        let callback = onEvent
        DispatchQueue.main.async {
            callback?(folderOpenEvent)
        }
    }

    private func logDecision(_ decision: PolicyDecision, for fileEvent: OpenFileEvent, ancestors: [AncestorInfo]) {
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
            "team_id=\(fileEvent.teamID)",
            "codesigning_id=\(fileEvent.signingID)",
            "ancestry_tree=\(ancestryTree)",
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
            let name = URL(fileURLWithPath: ancestor.path).lastPathComponent
            let user = resolveUserName(uid: ancestor.uid)
            let group = resolveGroupName(gid: ancestor.gid)
            return "process=\(name),processpath=\(ancestor.path),uid=\(ancestor.uid),user=\(user),gid=\(ancestor.gid),group=\(group),team_id=\(ancestor.teamID),codesigning_id=\(ancestor.signingID)"
        }
        return entries.map { "(\($0))" }.joined(separator: "->")
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
