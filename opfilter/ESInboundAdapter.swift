//
//  ESInboundAdapter.swift
//  opfilter
//

import Foundation
import EndpointSecurity
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "es-adapter")

final class ESInboundAdapter {
    private let interactor: FilterInteractor
    private let monitoredPath: String
    private var client: OpaquePointer?

    init(interactor: FilterInteractor, monitoredPath: String) {
        self.interactor = interactor
        self.monitoredPath = monitoredPath
    }

    func start() {
        let interactor = self.interactor
        let res = es_new_client(&client) { (esClient, message) in
            // If path data is unavailable for an open event, deny at the adapter boundary
            // before constructing a domain event.
            if message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN,
               message.pointee.event.open.file.pointee.path.data == nil {
                es_respond_flags_result(esClient, message, UInt32(message.pointee.event.open.fflag), false)
                return
            }
            interactor.handle(Self.filterEvent(from: message, esClient: esClient))
        }

        guard res == ES_NEW_CLIENT_RESULT_SUCCESS else {
            logger.fault("Failed to create ES client: \(res.rawValue)")
            exit(EXIT_FAILURE)
        }

        // Invert target-path muting so only muted prefixes generate events,
        // then mute our monitored path — the kernel now filters out everything
        // else before it reaches our callback.
        es_invert_muting(client!, ES_MUTE_INVERSION_TYPE_TARGET_PATH)
        es_mute_path(client!, monitoredPath, ES_MUTE_PATH_TYPE_TARGET_PREFIX)

        let eventTypes: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT,
        ]
        guard es_subscribe(client!, eventTypes, UInt32(eventTypes.count)) == ES_RETURN_SUCCESS else {
            logger.fault("Failed to subscribe to ES events")
            exit(EXIT_FAILURE)
        }

        logger.log("ESInboundAdapter started, monitoring: \(self.monitoredPath)")
        XPCClient.shared.reportMonitoringStatus(true)
    }

    private static func filterEvent(from message: UnsafePointer<es_message_t>, esClient: OpaquePointer) -> FilterEvent {
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_FORK:
            return .fork(child: processRecord(from: message.pointee.event.fork.child))
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            return .exec(newImage: processRecord(from: message.pointee.event.exec.target))
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            return .exit(pid: pid_t(message.pointee.process.pointee.audit_token.val.5))
        case ES_EVENT_TYPE_AUTH_OPEN:
            return .openFile(openFileEvent(from: message, esClient: esClient))
        default:
            fatalError("Received unsubscribed ES event type: \(message.pointee.event_type.rawValue)")
        }
    }

    private static func openFileEvent(from message: UnsafePointer<es_message_t>, esClient: OpaquePointer) -> OpenFileEvent {
        let process = message.pointee.process.pointee
        let file = message.pointee.event.open.file.pointee

        let ttyPath: String? = process.tty.map { string(from: $0.pointee.path) }.flatMap { $0.isEmpty ? nil : $0 }

        let respond: (Bool) -> Void = { allowed in
            es_respond_flags_result(esClient, message, allowed ? UInt32.max : 0, allowed)
        }

        return OpenFileEvent(
            path: string(from: file.path),
            processID: pid_t(bitPattern: process.audit_token.val.5),
            processPath: string(from: process.executable.pointee.path),
            teamID: string(from: process.team_id),
            signingID: string(from: process.signing_id),
            ttyPath: ttyPath,
            respond: respond
        )
    }

    private static func string(from esString: es_string_token_t) -> String {
        guard let data = esString.data else { return "" }
        return String(bytes: Data(bytes: data, count: esString.length), encoding: .utf8) ?? ""
    }
}
