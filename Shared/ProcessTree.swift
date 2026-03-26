//
//  ProcessTree.swift
//  Shared
//

import Foundation
import Security
import os

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

// MARK: - ProcessTreeProtocol

protocol ProcessTreeProtocol: AnyObject {
    func insert(_ record: ProcessRecord)
    func remove(identity: ProcessIdentity)
    func contains(identity: ProcessIdentity) -> Bool
    func ancestors(of identity: ProcessIdentity) -> [AncestorInfo]
    func allRecords() -> [ProcessRecord]
}

// MARK: - ProcessTree

final class ProcessTree: @unchecked Sendable, ProcessTreeProtocol {
    private struct State {
        var records: [ProcessIdentity: ProcessRecord] = [:]
        var pidIndex: [pid_t: ProcessIdentity] = [:]
        var ancestorCache: [ProcessIdentity: [AncestorInfo]] = [:]
    }

    private let storage = OSAllocatedUnfairLock(initialState: State())

    private static let postExitRetention: TimeInterval = 60
    private let evictionQueue: DispatchQueue

    init(evictionQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.process-tree-eviction")) {
        self.evictionQueue = evictionQueue
    }

    func insert(_ record: ProcessRecord) {
        storage.withLock { state in
            if let existing = state.pidIndex[record.identity.pid], existing != record.identity {
                state.records[existing] = nil
                state.ancestorCache[existing] = nil
            }
            state.records[record.identity] = record
            state.pidIndex[record.identity.pid] = record.identity
            state.ancestorCache[record.identity] = Self.buildAncestorChain(for: record, state: state)
        }
    }

    func remove(identity: ProcessIdentity) {
        evictionQueue.asyncAfter(deadline: .now() + Self.postExitRetention) { [self] in
            storage.withLock { state in
                state.records[identity] = nil
                state.ancestorCache[identity] = nil
                if state.pidIndex[identity.pid] == identity {
                    state.pidIndex[identity.pid] = nil
                }
            }
        }
    }

    func contains(identity: ProcessIdentity) -> Bool {
        storage.withLock { Self.lookup(identity, state: $0) != nil }
    }

    func ancestors(of identity: ProcessIdentity) -> [AncestorInfo] {
        storage.withLock { state in
            if let cached = state.ancestorCache[identity] { return cached }
            let resolved = Self.resolveIdentity(identity, state: state)
            return state.ancestorCache[resolved] ?? []
        }
    }

    func allRecords() -> [ProcessRecord] {
        storage.withLock { Array($0.records.values) }
    }

    private static func lookup(_ identity: ProcessIdentity, state: State) -> ProcessRecord? {
        if let record = state.records[identity] { return record }
        guard let indexed = state.pidIndex[identity.pid] else { return nil }
        return state.records[indexed]
    }

    private static func resolveIdentity(_ identity: ProcessIdentity, state: State) -> ProcessIdentity {
        if state.records[identity] != nil { return identity }
        guard let indexed = state.pidIndex[identity.pid], state.records[indexed] != nil else { return identity }
        return indexed
    }

    private static func buildAncestorChain(for record: ProcessRecord, state: State) -> [AncestorInfo] {
        let parentKey = resolveIdentity(record.parentIdentity, state: state)
        guard let parent = state.records[parentKey] else { return [] }
        let parentInfo = AncestorInfo(path: parent.path, teamID: parent.teamID, signingID: parent.signingID, uid: parent.uid, gid: parent.gid)
        guard let parentAncestors = state.ancestorCache[parentKey] else {
            return [parentInfo]
        }
        return [parentInfo] + parentAncestors
    }

    func buildInitialTree() {
        let estimatedCount = proc_listallpids(nil, 0)
        guard estimatedCount > 0 else { return }

        var pids = [pid_t](repeating: 0, count: Int(estimatedCount) + 64)
        let actualCount = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size)))
        guard actualCount > 0 else { return }

        var pidVersions: [pid_t: UInt32] = [:]
        pidVersions.reserveCapacity(actualCount)
        for pid in pids.prefix(actualCount) where pid > 0 {
            if let version = Self.pidVersion(of: pid) {
                pidVersions[pid] = version
            }
        }

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

        let pidIndexSnapshot = Dictionary(uniqueKeysWithValues: records.keys.map { ($0.pid, $0) })

        // Build ancestor cache using topological insertion order: parents before children.
        // Sort by PID as a heuristic — parent PIDs are typically lower than child PIDs.
        let sortedIdentities = records.keys.sorted { $0.pid < $1.pid }
        var ancestorCache: [ProcessIdentity: [AncestorInfo]] = [:]
        ancestorCache.reserveCapacity(records.count)
        var tempState = State(records: records, pidIndex: pidIndexSnapshot, ancestorCache: [:])
        for identity in sortedIdentities {
            guard let record = records[identity] else { continue }
            let chain = Self.buildAncestorChain(for: record, state: tempState)
            ancestorCache[identity] = chain
            tempState.ancestorCache[identity] = chain
        }

        storage.withLock { state in
            state.records = records
            state.pidIndex = pidIndexSnapshot
            state.ancestorCache = ancestorCache
        }
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
    let signingID = info[kSecCodeInfoIdentifier] as? String ?? ""
    let rawTeamID = info[kSecCodeInfoTeamIdentifier] as? String ?? ""
    let teamID = rawTeamID.isEmpty && !signingID.isEmpty ? "apple" : rawTeamID
    return (teamID, signingID)
}
