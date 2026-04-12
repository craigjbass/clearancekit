//
//  AuditLogger.swift
//  opfilter
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "faa")

// MARK: - AuditLogger

struct AuditLogger {
    func log(_ decision: PolicyDecision, for fileEvent: FileAuthEvent, ancestors: [AncestorInfo], dwellNanoseconds: UInt64, operationID: UUID = UUID()) {
        let line = formatEntry(decision, for: fileEvent, ancestors: ancestors, dwellNanoseconds: dwellNanoseconds, operationID: operationID)
        logger.log("\(line, privacy: .public)")
    }

    func formatEntry(_ decision: PolicyDecision, for fileEvent: FileAuthEvent, ancestors: [AncestorInfo], dwellNanoseconds: UInt64, operationID: UUID = UUID()) -> String {
        let decisionTag = decision.isAllowed ? "ALLOW" : "DENIED"
        let processName = URL(fileURLWithPath: fileEvent.processPath).lastPathComponent
        let policyVersion = policyVersionString(for: decision)
        let userName = resolveUserName(uid: fileEvent.uid)
        let groupName = resolveGroupName(gid: fileEvent.gid)
        let ancestryTree = formatAncestryTree(ancestors)

        var fields = [
            "action=FILE_ACCESS",
            "policy_version=\(policyVersion)",
            "policy_name=\(decision.policyName)",
            "path=\(fileEvent.path)",
        ]
        if let secondaryPath = fileEvent.secondaryPath {
            fields.append("secondary_path=\(secondaryPath)")
        }
        fields.append(contentsOf: [
            "access_type=\(fileEvent.operation.rawValue)",
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
            "team_id=\(resolveTeamID(teamID: fileEvent.teamID, signingID: fileEvent.signingID))",
            "codesigning_id=\(resolveSigningID(teamID: fileEvent.teamID, signingID: fileEvent.signingID))",
            "ancestry_tree=\(ancestryTree)",
            "dwell_ns=\(dwellNanoseconds)",
        ])
        return fields.joined(separator: "|")
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
            let team = resolveTeamID(teamID: ancestor.teamID, signingID: ancestor.signingID)
            let signing = resolveSigningID(teamID: ancestor.teamID, signingID: ancestor.signingID)
            return "user=\(user),signature=\(team):\(signing)"
        }
        return entries.map { "(\($0))" }.joined(separator: "->")
    }

    private func resolveTeamID(teamID: String, signingID: String) -> String {
        if teamID.isEmpty && signingID.isEmpty { return invalidSignature }
        return teamID
    }

    private func resolveSigningID(teamID: String, signingID: String) -> String {
        teamID.isEmpty && signingID.isEmpty ? invalidSignature : signingID
    }

    private func resolveUserName(uid: uid_t) -> String {
        guard let entry = getpwuid(uid) else { return "\(uid)" }
        return String(cString: entry.pointee.pw_name)
    }

    private func resolveGroupName(gid: gid_t) -> String {
        guard let entry = getgrgid(gid) else { return "\(gid)" }
        return String(cString: entry.pointee.gr_name)
    }
}
