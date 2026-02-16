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

// Start XPC server before ES client
XPCServer.shared.start()

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
    let denyReason = checkFAAPolicy(path: path, processPath: processPath, teamID: teamID, signingID: signingID)
    let allowed = denyReason == nil

    // Respond immediately — the ES deadline is strict and all work after
    // this point (logging, TTY output, XPC broadcast) is non-critical I/O.
    es_respond_flags_result(client, message, allowed ? UInt32(openEvent.fflag) : 0, false)

    if allowed {
        logger.info("FAA ALLOW: \(path) accessed by \(processPath) (team: \(teamID), signing: \(signingID))")
    } else {
        logger.error("FAA DENY: \(path) accessed by \(processPath) (team: \(teamID), signing: \(signingID))")

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
        XPCServer.shared.broadcastEvent(event)
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

// Broadcast that monitoring is now active
XPCServer.shared.broadcastMonitoringStatus(true)

dispatchMain()
