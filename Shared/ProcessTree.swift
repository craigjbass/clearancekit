//
//  ProcessTree.swift
//  Shared
//

import Foundation
import Security
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "process-tree")

// MARK: - ProcessIdentity

struct ProcessIdentity: Hashable {
    let pid: pid_t
    let pidVersion: UInt32
}

// MARK: - ProcessRecord

struct ProcessRecord {
    let identity: ProcessIdentity
    let parentIdentity: ProcessIdentity
    let path: String
    let teamID: String
    let signingID: String
    let uid: uid_t
    let gid: gid_t
}

// MARK: - ProcessTree

final class ProcessTree: @unchecked Sendable {
    static let shared = ProcessTree()

    private let storage = OSAllocatedUnfairLock(initialState: [ProcessIdentity: ProcessRecord]())

    /// Reverse index: PID → current ProcessIdentity. Kept in sync with `storage`
    /// so that lookups from initial-scan entries (pidversion 0 parent references)
    /// can resolve to the live ES-sourced identity.
    private let pidIndex = OSAllocatedUnfairLock(initialState: [pid_t: ProcessIdentity]())

    private static let postExitRetention: TimeInterval = 60
    private let evictionQueue = DispatchQueue(label: "uk.craigbass.clearancekit.process-tree-eviction")

    func insert(_ record: ProcessRecord) {
        storage.withLock { tree in
            // Remove any stale entry for the same PID (e.g. initial-scan placeholder
            // being replaced by a live ES event with the real pidversion).
            if let existing = pidIndex.withLock({ $0[record.identity.pid] }), existing != record.identity {
                tree[existing] = nil
                logger.debug("ProcessTree: replaced stale entry pid=\(existing.pid) pidversion=\(existing.pidVersion) with pidversion=\(record.identity.pidVersion)")
            }
            tree[record.identity] = record
        }
        pidIndex.withLock { $0[record.identity.pid] = record.identity }
        logger.debug("ProcessTree: insert pid=\(record.identity.pid) pidversion=\(record.identity.pidVersion) parent_pid=\(record.parentIdentity.pid) parent_pidversion=\(record.parentIdentity.pidVersion) path=\(record.path, privacy: .public)")
    }

    /// Schedules deferred eviction of a process record. The entry is retained
    /// for 60 seconds after exit so ancestor lookups remain available even if
    /// a parent exits shortly before its child's AUTH_OPEN is processed.
    func remove(identity: ProcessIdentity) {
        evictionQueue.asyncAfter(deadline: .now() + Self.postExitRetention) { [self] in
            storage.withLock { tree in
                tree[identity] = nil
            }
            pidIndex.withLock { index in
                // Only clear the PID index if it still points to the exited process.
                // A new process may have already claimed this PID via insert().
                if index[identity.pid] == identity {
                    index[identity.pid] = nil
                }
            }
        }
    }

    func contains(identity: ProcessIdentity) -> Bool {
        storage.withLock { lookup(identity, in: $0) != nil }
    }

    /// Returns ancestor chain for the given process, from immediate parent upward,
    /// stopping when a process is not present in the tree or a cycle is detected.
    func ancestors(of identity: ProcessIdentity) -> [AncestorInfo] {
        storage.withLock { tree in
            var result: [AncestorInfo] = []
            var current = identity
            var seen: Set<ProcessIdentity> = [current]

            while let record = lookup(current, in: tree) {
                let parentKey = resolve(record.parentIdentity, in: tree)
                guard !seen.contains(parentKey) else { break }
                seen.insert(parentKey)
                guard let parent = lookup(parentKey, in: tree) else { break }
                result.append(AncestorInfo(path: parent.path, teamID: parent.teamID, signingID: parent.signingID, uid: parent.uid, gid: parent.gid))
                current = parentKey
            }

            return result
        }
    }

    /// Look up a record by exact identity first, falling back to the PID index
    /// (handles initial-scan entries whose pidversion is 0).
    private func lookup(_ identity: ProcessIdentity, in tree: [ProcessIdentity: ProcessRecord]) -> ProcessRecord? {
        if let record = tree[identity] { return record }
        guard let indexed = pidIndex.withLock({ $0[identity.pid] }) else { return nil }
        return tree[indexed]
    }

    /// Resolve an identity to the canonical one stored in the PID index, so that
    /// parent references from initial-scan entries (pidversion 0) find the live record.
    private func resolve(_ identity: ProcessIdentity, in tree: [ProcessIdentity: ProcessRecord]) -> ProcessIdentity {
        if tree[identity] != nil { return identity }
        guard let indexed = pidIndex.withLock({ $0[identity.pid] }), tree[indexed] != nil else { return identity }
        return indexed
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

        // First pass: obtain pidversion for every PID via TASK_AUDIT_TOKEN so
        // parent identities can be resolved precisely in the second pass.
        var pidVersions: [pid_t: UInt32] = [:]
        pidVersions.reserveCapacity(actualCount)
        for pid in pids.prefix(actualCount) where pid > 0 {
            if let version = Self.pidVersion(of: pid) {
                pidVersions[pid] = version
            }
        }

        // Second pass: build records keyed by ProcessIdentity.
        var records: [ProcessIdentity: ProcessRecord] = [:]
        records.reserveCapacity(actualCount)

        for pid in pids.prefix(actualCount) where pid > 0 {
            var bsdInfo = proc_bsdinfo()
            guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdInfo, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0 else { continue }

            let parentPID = pid_t(bsdInfo.pbi_ppid)
            let identity = ProcessIdentity(pid: pid, pidVersion: pidVersions[pid] ?? 0)
            let parentIdentity = ProcessIdentity(pid: parentPID, pidVersion: pidVersions[parentPID] ?? 0)

            var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            let pathLen = proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN))
            let path = pathLen > 0 ? String(cString: pathBuffer) : ""

            let (teamID, signingID): (String, String)
            if let code = secCode(forPID: pid) {
                (teamID, signingID) = codeSigningInfo(for: code)
            } else {
                (teamID, signingID) = ("", "")
            }

            records[identity] = ProcessRecord(identity: identity, parentIdentity: parentIdentity, path: path, teamID: teamID, signingID: signingID, uid: bsdInfo.pbi_uid, gid: bsdInfo.pbi_gid)
        }

        let snapshot = records
        let index = Dictionary(uniqueKeysWithValues: snapshot.keys.map { ($0.pid, $0) })
        storage.withLock { $0 = snapshot }
        pidIndex.withLock { $0 = index }
        logger.info("ProcessTree: initial scan complete — \(snapshot.count) processes")
    }

    /// Obtains the pidversion for a running process via its Mach task audit token.
    private static func pidVersion(of pid: pid_t) -> UInt32? {
        var task = mach_port_t()
        guard task_name_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, task) }

        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &token) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                task_info(task, task_flavor_t(TASK_AUDIT_TOKEN), intPtr, &count)
            }
        }
        guard result == KERN_SUCCESS else { return nil }
        return token.val.7
    }
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
