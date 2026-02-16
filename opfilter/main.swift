//
//  main.swift
//  opfilter
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation
import EndpointSecurity

let monitoredPath = "/opt/clearancekit"

// Start XPC server before ES client
XPCServer.shared.start()

var client: OpaquePointer?

// Create the client
let res = es_new_client(&client) { (client, message) in
    let eventType = message.pointee.event_type

    if eventType == ES_EVENT_TYPE_AUTH_OPEN {
        let openEvent = message.pointee.event.open
        let file = openEvent.file.pointee

        // Get the path from the file
        let pathLength = file.path.length
        guard let pathData = file.path.data else {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            return
        }
        let path = String(bytes: Data(bytes: pathData, count: pathLength), encoding: .utf8) ?? ""

        if path.hasPrefix(monitoredPath) {
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

            if allowed {
                NSLog("FAA ALLOW: %@ accessed by %@ (team: %@, signing: %@)", path, processPath, teamID, signingID)
            } else {
                NSLog("FAA DENY: %@ accessed by %@ (team: %@, signing: %@)", path, processPath, teamID, signingID)

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

            // Respond with allow or deny
            es_respond_auth_result(client, message, allowed ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)

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
        } else {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
        }
    }
}

if res != ES_NEW_CLIENT_RESULT_SUCCESS {
    NSLog("Failed to create ES client: %d", res.rawValue)
    exit(EXIT_FAILURE)
}

// Subscribe to open events
let subscribeResult = es_subscribe(client!, [ES_EVENT_TYPE_AUTH_OPEN], 1)
if subscribeResult != ES_RETURN_SUCCESS {
    NSLog("Failed to subscribe to events: %d", subscribeResult.rawValue)
    exit(EXIT_FAILURE)
}

NSLog("opfilter started, monitoring: %@", monitoredPath)

// Broadcast that monitoring is now active
XPCServer.shared.broadcastMonitoringStatus(true)

dispatchMain()
