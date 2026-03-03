//
//  main.swift
//  opfilter
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation
import EndpointSecurity
import Security
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "faa")

let monitoredPath = "/opt/clearancekit"

// MARK: - Process ancestry

/// Returns a SecCode for a process identified by audit token.
/// Using an audit token (rather than a bare PID) prevents TOCTOU races
/// from PID recycling, as the token encodes both the PID and its version.
private func secCode(forAuditToken token: audit_token_t) -> SecCode? {
    var mutableToken = token
    let data = Data(bytes: &mutableToken, count: MemoryLayout<audit_token_t>.size)
    let attrs = [kSecGuestAttributeAudit: data] as CFDictionary
    var code: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(rawValue: 0), &code) == errSecSuccess else { return nil }
    return code
}

/// Returns a SecCode for a process identified by PID alone.
/// Only use this when an audit token is unavailable (grandparent and above).
private func secCode(forPID pid: pid_t) -> SecCode? {
    let attrs = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
    var code: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(rawValue: 0), &code) == errSecSuccess else { return nil }
    return code
}

/// Extracts team ID and signing ID from a SecCode.
private func codeSigningInfo(for code: SecCode) -> (teamID: String, signingID: String) {
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

/// Walks the process tree upward from the given process, returning an AncestorInfo
/// for each ancestor up to (but not including) launchd.
///
/// - The direct parent uses the ES-provided audit token, which is immune to PID
///   recycling because it encodes both PID and a per-instance version counter.
/// - Grandparent and above are located via proc_pidinfo PIDs. Audit tokens are
///   unavailable for those levels from the ES event, so PID recycling is
///   theoretically possible beyond the first ancestor — though very unlikely for
///   long-lived processes (shells, IDEs) that are typical ancestors of interest.
private func getProcessAncestors(processAuditToken: audit_token_t, parentAuditToken: audit_token_t) -> [AncestorInfo] {
    var ancestors: [AncestorInfo] = []

    // Direct parent: use audit token from the ES event.
    let parentPID = pid_t(parentAuditToken.val.5)
    guard parentPID > 1 else { return ancestors }

    var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    let pathLen = proc_pidpath(parentPID, &pathBuffer, UInt32(MAXPATHLEN))
    let parentPath = pathLen > 0 ? String(cString: pathBuffer) : ""

    var parentTeamID = ""
    var parentSigningID = ""
    if let code = secCode(forAuditToken: parentAuditToken) {
        (parentTeamID, parentSigningID) = codeSigningInfo(for: code)
    }
    ancestors.append(AncestorInfo(path: parentPath, teamID: parentTeamID, signingID: parentSigningID))

    // Grandparent and above: walk via proc_pidinfo.
    var seen: Set<pid_t> = [pid_t(processAuditToken.val.5), parentPID]
    var currentPID = parentPID

    while true {
        var bsdInfo = proc_bsdinfo()
        let ret = proc_pidinfo(currentPID, PROC_PIDTBSDINFO, 0, &bsdInfo, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard ret > 0 else { break }

        let ancestorPID = pid_t(bsdInfo.pbi_ppid)
        guard ancestorPID > 1, !seen.contains(ancestorPID) else { break }
        seen.insert(ancestorPID)

        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let len = proc_pidpath(ancestorPID, &buf, UInt32(MAXPATHLEN))
        let ancestorPath = len > 0 ? String(cString: buf) : ""

        var ancestorTeamID = ""
        var ancestorSigningID = ""
        if let code = secCode(forPID: ancestorPID) {
            (ancestorTeamID, ancestorSigningID) = codeSigningInfo(for: code)
        }
        ancestors.append(AncestorInfo(path: ancestorPath, teamID: ancestorTeamID, signingID: ancestorSigningID))

        currentPID = ancestorPID
    }

    return ancestors
}

// MARK: - ES client

// Connect to the LaunchDaemon before starting the ES client
XPCClient.shared.start()

var client: OpaquePointer?

// Create the client — only events matching the muted (inverted) path prefix
// will be delivered, so every event here is for a file under monitoredPath.
let res = es_new_client(&client) { (client, message) in
    let openEvent = message.pointee.event.open
    let file = openEvent.file.pointee

    // Get the path from the file
    let pathLength = file.path.length
    guard let pathData = file.path.data else {
        es_respond_flags_result(client, message, UInt32(openEvent.fflag), false)
        return
    }
    let path = String(bytes: Data(bytes: pathData, count: pathLength), encoding: .utf8) ?? ""

    // Extract process information
    let process = message.pointee.process.pointee
    let processID = Int32(bitPattern: process.audit_token.val.5)

    var processPath = ""
    if let execPathData = process.executable.pointee.path.data {
        let execPathLength = process.executable.pointee.path.length
        processPath = String(bytes: Data(bytes: execPathData, count: execPathLength), encoding: .utf8) ?? ""
    }

    var teamID = ""
    if let teamIDData = process.team_id.data {
        teamID = String(bytes: Data(bytes: teamIDData, count: process.team_id.length), encoding: .utf8) ?? ""
    }

    var signingID = ""
    if let signingIDData = process.signing_id.data {
        signingID = String(bytes: Data(bytes: signingIDData, count: process.signing_id.length), encoding: .utf8) ?? ""
    }

    // Check FAA policy
    let ancestors = getProcessAncestors(
        processAuditToken: process.audit_token,
        parentAuditToken: process.parent_audit_token
    )
    let denyReason = checkFAAPolicy(path: path, processPath: processPath, teamID: teamID, signingID: signingID, ancestors: ancestors)
    let allowed = denyReason == nil

    // Respond immediately — the ES deadline is strict and all work after
    // this point (logging, TTY output, XPC broadcast) is non-critical I/O.
    // Cache allow results: the kernel will skip the callback for the same
    // (process audit token, file vnode) pair on subsequent opens, avoiding
    // redundant policy evaluation. Denials are never cached so that a policy
    // change to allow is reflected immediately without requiring es_clear_cache.
    es_respond_flags_result(client, message, allowed ? UInt32(openEvent.fflag) : 0, allowed)

    let ancestryDescription = ancestors.isEmpty ? "none" : ancestors.map { "\($0.path) (team: \($0.teamID), signing: \($0.signingID))" }.joined(separator: " -> ")

    if allowed {
        logger.info("FAA ALLOW: \(path) accessed by \(processPath) (team: \(teamID), signing: \(signingID)) ancestry: \(ancestryDescription)")
    } else {
        logger.error("FAA DENY: \(path) accessed by \(processPath) (team: \(teamID), signing: \(signingID)) ancestry: \(ancestryDescription)")

        // Write denial reason to the process's TTY
        if let tty = process.tty {
            if let ttyData = tty.pointee.path.data {
                let ttyPath = String(bytes: Data(bytes: ttyData, count: tty.pointee.path.length), encoding: .utf8) ?? ""
                if !ttyPath.isEmpty, let fh = FileHandle(forWritingAtPath: ttyPath) {
                    let msg = "\n[clearancekit] Access denied: \(path)\n  \(denyReason!)\n"
                    if let data = msg.data(using: .utf8) {
                        fh.write(data)
                    }
                    // Send SIGWINCH to the foreground process group to trigger a shell prompt redraw
                    let fd = fh.fileDescriptor
                    let pgrp = tcgetpgrp(fd)
                    if pgrp > 0 {
                        killpg(pgrp, SIGWINCH)
                    }
                    fh.closeFile()
                }
            }
        }
    }

    // Broadcast the event to the UI
    let event = FolderOpenEvent(
        path: path,
        timestamp: Date(),
        processID: processID,
        processPath: processPath,
        teamID: teamID,
        signingID: signingID,
        accessAllowed: allowed
    )

    DispatchQueue.main.async {
        XPCClient.shared.reportEvent(event)
    }
}

if res != ES_NEW_CLIENT_RESULT_SUCCESS {
    logger.fault("Failed to create ES client: \(res.rawValue)")
    exit(EXIT_FAILURE)
}

// Invert target-path muting so only muted prefixes generate events,
// then mute our monitored path — the kernel now filters out everything
// else before it reaches our callback.
es_invert_muting(client!, ES_MUTE_INVERSION_TYPE_TARGET_PATH)
es_mute_path(client!, monitoredPath, ES_MUTE_PATH_TYPE_TARGET_PREFIX)

// Subscribe to open events
let subscribeResult = es_subscribe(client!, [ES_EVENT_TYPE_AUTH_OPEN], 1)
if subscribeResult != ES_RETURN_SUCCESS {
    logger.fault("Failed to subscribe to events: \(subscribeResult.rawValue)")
    exit(EXIT_FAILURE)
}

logger.log("opfilter started, monitoring: \(monitoredPath)")

// Notify daemon that monitoring is now active
XPCClient.shared.reportMonitoringStatus(true)

dispatchMain()
