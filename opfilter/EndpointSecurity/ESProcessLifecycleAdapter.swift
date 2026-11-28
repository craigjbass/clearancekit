//
//  ESProcessLifecycleAdapter.swift
//  opfilter
//

import EndpointSecurity
import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "process-lifecycle")

protocol ProcessLifecycleHandler: AnyObject {
    func handleFork(child: ProcessRecord)
    func handleExec(newImage: ProcessRecord)
    func handleExit(identity: ProcessIdentity)
}

// The file-access client inverts target-path muting so that only protected
// paths generate events. ES applies that inversion to the exec target too, so
// an exec of an unprotected executable never reaches that client. This client
// has no muting, so the process tree gets every exec.
final class ESProcessLifecycleAdapter {
    private let esAPI: any EndpointSecurityAPI
    private let handler: any ProcessLifecycleHandler
    private var client: OpaquePointer?

    init(esAPI: any EndpointSecurityAPI, handler: any ProcessLifecycleHandler) {
        self.esAPI = esAPI
        self.handler = handler
    }

    func start() {
        let handler = self.handler

        let (newClient, result) = esAPI.newClient { _, message in
            switch message.pointee.event_type {
            case ES_EVENT_TYPE_NOTIFY_FORK:
                handler.handleFork(child: processRecord(from: message.pointee.event.fork.child))
            case ES_EVENT_TYPE_NOTIFY_EXEC:
                handler.handleExec(newImage: processRecord(from: message.pointee.event.exec.target))
            case ES_EVENT_TYPE_NOTIFY_EXIT:
                let token = message.pointee.process.pointee.audit_token
                handler.handleExit(identity: ProcessIdentity(pid: pid_t(token.val.5), pidVersion: token.val.7))
            default:
                fatalError("ESProcessLifecycleAdapter: received unsubscribed event type \(message.pointee.event_type.rawValue)")
            }
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let newClient else {
            logger.fault("ESProcessLifecycleAdapter: failed to create ES client (\(result.rawValue, privacy: .public))")
            exit(EXIT_FAILURE)
        }

        client = newClient

        guard esAPI.subscribe(newClient, to: [
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT,
        ]) == ES_RETURN_SUCCESS else {
            logger.fault("ESProcessLifecycleAdapter: failed to subscribe to ES events")
            exit(EXIT_FAILURE)
        }
    }
}
