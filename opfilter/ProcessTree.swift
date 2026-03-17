//
//  ProcessTree.swift
//  opfilter
//

import Foundation
import EndpointSecurity
import Security
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "process-tree")

// MARK: - ProcessRecord

struct ProcessRecord {
    let pid: pid_t
    let parentPID: pid_t
    let path: String
    let teamID: String
    let signingID: String
    let uid: uid_t
    let gid: gid_t
}

// MARK: - ProcessTree

final class ProcessTree: @unchecked Sendable {
    static let shared = ProcessTree()

    private let storage = OSAllocatedUnfairLock(initialState: [pid_t: ProcessRecord]())

    private init() {}

    func insert(_ record: ProcessRecord) {
        storage.withLock { $0[record.pid] = record }
    }

    func remove(pid: pid_t) {
        storage.withLock { $0[pid] = nil }
    }

    func contains(pid: pid_t) -> Bool {
        storage.withLock { $0[pid] != nil }
    }

    /// Returns ancestor chain for the given PID, from immediate parent upward,
    /// stopping when a PID is not present in the tree or a cycle is detected.
    func ancestors(ofPID pid: pid_t) -> [AncestorInfo] {
        storage.withLock { tree in
            var result: [AncestorInfo] = []
            var currentPID = pid
            var seen: Set<pid_t> = [currentPID]

            while let record = tree[currentPID] {
                guard !seen.contains(record.parentPID) else { break }
                seen.insert(record.parentPID)
                guard let parent = tree[record.parentPID] else { break }
                result.append(AncestorInfo(path: parent.path, teamID: parent.teamID, signingID: parent.signingID, uid: parent.uid, gid: parent.gid))
                currentPID = record.parentPID
            }

            return result
        }
    }

    /// Populates the tree by scanning all processes currently running on the system.
    /// This is inherently racy — processes may start or exit during enumeration —
    /// but NOTIFY_FORK / NOTIFY_EXEC / NOTIFY_EXIT events keep it accurate
    /// once the ES client is subscribed.
    func buildInitialTree() {
        let estimatedCount = proc_listallpids(nil, 0)
        guard estimatedCount > 0 else { return }

        // Allocate with headroom: new processes can appear between the count
        // call and the list call.
        var pids = [pid_t](repeating: 0, count: Int(estimatedCount) + 64)
        let actualCount = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size)))
        guard actualCount > 0 else { return }

        var records: [pid_t: ProcessRecord] = [:]
        records.reserveCapacity(actualCount)

        for pid in pids.prefix(actualCount) where pid > 0 {
            var bsdInfo = proc_bsdinfo()
            guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdInfo, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0 else { continue }

            let parentPID = pid_t(bsdInfo.pbi_ppid)

            var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            let pathLen = proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN))
            let path = pathLen > 0 ? String(cString: pathBuffer) : ""

            let (teamID, signingID): (String, String)
            if let code = secCode(forPID: pid) {
                (teamID, signingID) = codeSigningInfo(for: code)
            } else {
                (teamID, signingID) = ("", "")
            }

            records[pid] = ProcessRecord(pid: pid, parentPID: parentPID, path: path, teamID: teamID, signingID: signingID, uid: bsdInfo.pbi_uid, gid: bsdInfo.pbi_gid)
        }

        let snapshot = records
        storage.withLock { $0 = snapshot }
        logger.info("ProcessTree: initial scan complete — \(snapshot.count) processes")
    }
}

// MARK: - ProcessRecord from ES event

/// Extracts a ProcessRecord directly from an ES process pointer.
/// All fields are sourced from the ES-provided data; no secondary proc_pidinfo call needed.
func processRecord(from esProcess: UnsafeMutablePointer<es_process_t>) -> ProcessRecord {
    let process = esProcess.pointee
    let pid = pid_t(process.audit_token.val.5)
    let parentPID = pid_t(process.parent_audit_token.val.5)

    let path: String
    if let data = process.executable.pointee.path.data {
        path = String(bytes: Data(bytes: data, count: process.executable.pointee.path.length), encoding: .utf8) ?? ""
    } else {
        path = ""
    }

    let teamID: String
    if let data = process.team_id.data {
        teamID = String(bytes: Data(bytes: data, count: process.team_id.length), encoding: .utf8) ?? ""
    } else {
        teamID = ""
    }

    let signingID: String
    if let data = process.signing_id.data {
        signingID = String(bytes: Data(bytes: data, count: process.signing_id.length), encoding: .utf8) ?? ""
    } else {
        signingID = ""
    }

    let uid = uid_t(process.audit_token.val.1)
    let gid = gid_t(process.audit_token.val.2)

    return ProcessRecord(pid: pid, parentPID: parentPID, path: path, teamID: teamID, signingID: signingID, uid: uid, gid: gid)
}

// MARK: - Code signing helpers

func secCode(forAuditToken token: audit_token_t) -> SecCode? {
    var mutableToken = token
    let data = Data(bytes: &mutableToken, count: MemoryLayout<audit_token_t>.size)
    let attrs = [kSecGuestAttributeAudit: data] as CFDictionary
    var code: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(rawValue: 0), &code) == errSecSuccess else { return nil }
    return code
}

func secCode(forPID pid: pid_t) -> SecCode? {
    let attrs = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
    var code: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(rawValue: 0), &code) == errSecSuccess else { return nil }
    return code
}

func codeSigningInfo(for code: SecCode) -> (teamID: String, signingID: String) {
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, SecCSFlags(rawValue: 0), &staticCode) == errSecSuccess,
          let staticCode else { return ("", "") }
    var dict: CFDictionary?
    // kSecCSSigningInformation = 2: request team ID, signing identifier, etc.
    guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: 2), &dict) == errSecSuccess,
          let info = dict as? [CFString: Any] else { return ("", "") }
    let teamID = info[kSecCodeInfoTeamIdentifier] as? String ?? ""
    let signingID = info[kSecCodeInfoIdentifier] as? String ?? ""
    return (teamID, signingID)
}
