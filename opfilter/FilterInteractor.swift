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
    let processPath: String
    let teamID: String
    let signingID: String
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
        if isGloballyAllowed(
            allowlist: allowlist,
            processPath: fileEvent.processPath,
            signingID: fileEvent.signingID,
            teamID: fileEvent.teamID
        ) {
            fileEvent.respond(true)
            return
        }

        let rules = rulesStorage.withLock { $0 }
        let ancestors = ProcessTree.shared.ancestors(ofPID: fileEvent.processID)
        let decision = checkFAAPolicy(
            rules: rules,
            path: fileEvent.path,
            processPath: fileEvent.processPath,
            teamID: fileEvent.teamID,
            signingID: fileEvent.signingID,
            ancestors: ancestors
        )
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
        let ancestryDescription = ancestors.isEmpty
            ? "none"
            : ancestors.map { "\($0.path) (team: \($0.teamID), signing: \($0.signingID))" }.joined(separator: " -> ")
        let tag = decision.isAllowed ? "ALLOW" : "DENY"
        let line = "FAA \(tag): \(fileEvent.path) accessed by \(fileEvent.processPath) (team: \(fileEvent.teamID), signing: \(fileEvent.signingID)) ancestry: \(ancestryDescription) reason: \(decision.reason)"

        if decision.isAllowed {
            logger.info("\(line, privacy: .public)")
        } else {
            logger.error("\(line, privacy: .public)")
        }
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
