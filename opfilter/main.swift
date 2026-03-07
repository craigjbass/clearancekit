//
//  main.swift
//  opfilter
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation
import EndpointSecurity
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "faa")

let monitoredPath = "/opt/clearancekit"

// MARK: - ES client

// Connect to the LaunchDaemon before starting the ES client
XPCClient.shared.start()

// Populate process ancestry from existing processes before subscribing to ES events.
// NOTIFY_FORK / NOTIFY_EXEC / NOTIFY_EXIT will keep the tree accurate from here on.
ProcessTree.shared.buildInitialTree()

var client: OpaquePointer?

let res = es_new_client(&client) { (client, message) in
    switch message.pointee.event_type {

    case ES_EVENT_TYPE_NOTIFY_FORK:
        ProcessTree.shared.insert(processRecord(from: message.pointee.event.fork.child))

    case ES_EVENT_TYPE_NOTIFY_EXEC:
        // target is the new process image; PID and parent are unchanged.
        ProcessTree.shared.insert(processRecord(from: message.pointee.event.exec.target))

    case ES_EVENT_TYPE_NOTIFY_EXIT:
        let pid = pid_t(message.pointee.process.pointee.audit_token.val.5)
        ProcessTree.shared.remove(pid: pid)

    case ES_EVENT_TYPE_AUTH_OPEN:
        handleOpenEvent(client: client, message: message)

    default:
        break
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

// Subscribe to open events and the process lifecycle events needed to maintain
// the process tree. FORK/EXEC/EXIT are NOTIFY-only; AUTH_OPEN requires a response.
let eventTypes: [es_event_type_t] = [
    ES_EVENT_TYPE_AUTH_OPEN,
    ES_EVENT_TYPE_NOTIFY_FORK,
    ES_EVENT_TYPE_NOTIFY_EXEC,
    ES_EVENT_TYPE_NOTIFY_EXIT,
]
let subscribeResult = es_subscribe(client!, eventTypes, UInt32(eventTypes.count))
if subscribeResult != ES_RETURN_SUCCESS {
    logger.fault("Failed to subscribe to events: \(subscribeResult.rawValue)")
    exit(EXIT_FAILURE)
}

logger.log("opfilter started, monitoring: \(monitoredPath)")

// Notify daemon that monitoring is now active
XPCClient.shared.reportMonitoringStatus(true)

dispatchMain()

// MARK: - Open event handler

private func handleOpenEvent(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
    let openEvent = message.pointee.event.open
    let file = openEvent.file.pointee

    let pathLength = file.path.length
    guard let pathData = file.path.data else {
        es_respond_flags_result(client, message, UInt32(openEvent.fflag), false)
        return
    }
    let path = String(bytes: Data(bytes: pathData, count: pathLength), encoding: .utf8) ?? ""

    let process = message.pointee.process.pointee
    let processID = pid_t(bitPattern: process.audit_token.val.5)

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

    let ancestors = ProcessTree.shared.ancestors(ofPID: processID)
    let decision = checkFAAPolicy(path: path, processPath: processPath, teamID: teamID, signingID: signingID, ancestors: ancestors)
    let allowed = decision.isAllowed

    // Respond immediately — the ES deadline is strict and all work after
    // this point (logging, TTY output, XPC broadcast) is non-critical I/O.
    // Use UINT32_MAX for allow, not the event's fflag value. The SDK documents
    // this explicitly: cached authorized_flags are compared as a superset check
    // against future cache hits, so caching a specific fflag value will deny
    // any subsequent open on the same (process, file) pair that requests flags
    // not present in the cached value — even if our policy would allow it.
    // Denials are never cached so that a policy change to allow takes effect
    // immediately without needing es_clear_cache.
    es_respond_flags_result(client, message, allowed ? UInt32.max : 0, allowed)

    let ancestryDescription = ancestors.isEmpty
        ? "none"
        : ancestors.map { "\($0.path) (team: \($0.teamID), signing: \($0.signingID))" }.joined(separator: " -> ")

    if allowed {
        logger.info("FAA ALLOW: \(path, privacy: .public) accessed by \(processPath, privacy: .public) (team: \(teamID, privacy: .public), signing: \(signingID, privacy: .public)) ancestry: \(ancestryDescription, privacy: .public) reason: \(decision.reason, privacy: .public)")
    } else {
        logger.error("FAA DENY: \(path, privacy: .public) accessed by \(processPath, privacy: .public) (team: \(teamID, privacy: .public), signing: \(signingID, privacy: .public)) ancestry: \(ancestryDescription, privacy: .public) reason: \(decision.reason, privacy: .public)")

        // Write denial reason to the process's TTY
        if let tty = process.tty {
            if let ttyData = tty.pointee.path.data {
                let ttyPath = String(bytes: Data(bytes: ttyData, count: tty.pointee.path.length), encoding: .utf8) ?? ""
                if !ttyPath.isEmpty, let fh = FileHandle(forWritingAtPath: ttyPath) {
                    let msg = "\n[clearancekit] Access denied: \(path)\n  \(decision.reason)\n"
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
        accessAllowed: allowed,
        decisionReason: decision.reason,
        ancestors: ancestors
    )

    DispatchQueue.main.async {
        XPCClient.shared.reportEvent(event)
    }
}
