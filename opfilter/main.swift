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

        // Check if this is a directory within our monitored path
        let isDirectory = (file.stat.st_mode & S_IFMT) == S_IFDIR

        if isDirectory && path.hasPrefix(monitoredPath) {
            NSLog("Folder opened in monitored path: %@", path)

            // Extract process information
            let process = message.pointee.process.pointee
            // PID is at index 5 in the audit token
            let processID = Int32(bitPattern: process.audit_token.val.5)

            var processPath = ""
            if let execPathData = process.executable.pointee.path.data {
                let execPathLength = process.executable.pointee.path.length
                processPath = String(bytes: Data(bytes: execPathData, count: execPathLength), encoding: .utf8) ?? ""
            }

            // Create and broadcast the event
            let event = FolderOpenEvent(
                path: path,
                timestamp: Date(),
                processID: processID,
                processPath: processPath
            )

            DispatchQueue.main.async {
                XPCServer.shared.broadcastEvent(event)
            }
        }

        // Allow the operation
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
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
