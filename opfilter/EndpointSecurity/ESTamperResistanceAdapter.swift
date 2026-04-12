//
//  ESTamperResistanceAdapter.swift
//  opfilter
//
//  Subscribes to ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME and
//  ES_EVENT_TYPE_AUTH_SIGNAL, denying both when the target is the opfilter
//  process itself. All other targets are allowed and cached.
//
//  Responding inline in the ES callback (no async dispatch) minimises the
//  window between event delivery and response for tamper events.
//

import EndpointSecurity
import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "tamper-resistance")

private func isTrustedBySignature(_ process: UnsafeMutablePointer<es_process_t>) -> Bool {
    let p = process.pointee
    let signingID = esString(p.signing_id)
    if p.is_platform_binary && signingID == "com.apple.xpc.launchd" { return true }
    let teamID = esString(p.team_id)
    if teamID == XPCConstants.teamID && signingID == XPCConstants.serviceName { return true }
    return false
}

private func esString(_ token: es_string_token_t) -> String {
    guard let data = token.data else { return "" }
    return String(bytes: Data(bytes: data, count: token.length), encoding: .utf8) ?? ""
}

private func esEventTypeName(_ type: es_event_type_t) -> String {
    switch type {
    case ES_EVENT_TYPE_AUTH_SIGNAL: return "signal"
    case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME: return "proc_suspend_resume"
    default: return "unknown"
    }
}

final class ESTamperResistanceAdapter {
    var onTamperDenied: ((TamperAttemptEvent) -> Void)?

    private let ownPID: pid_t
    private let ownParentPID: pid_t
    private let esAPI: any EndpointSecurityAPI
    private var client: OpaquePointer?

    init(
        ownPID: pid_t = getpid(),
        ownParentPID: pid_t = getppid(),
        esAPI: any EndpointSecurityAPI
    ) {
        self.ownPID = ownPID
        self.ownParentPID = ownParentPID
        self.esAPI = esAPI
    }

    func start() {
        let ownPID = self.ownPID
        let ownParentPID = self.ownParentPID
        let esAPI = self.esAPI
        let onTamperDenied = self.onTamperDenied

        let (newClient, result) = esAPI.newClient { esClient, message in
            esAPI.retainMessage(message)

            let targetPID: pid_t
            switch message.pointee.event_type {
            case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
                targetPID = pid_t(message.pointee.event.proc_suspend_resume.target!.pointee.audit_token.val.5)
            case ES_EVENT_TYPE_AUTH_SIGNAL:
                targetPID = pid_t(message.pointee.event.signal.target.pointee.audit_token.val.5)
            default:
                fatalError("ESTamperResistanceAdapter: received unsubscribed event type \(message.pointee.event_type.rawValue)")
            }

            guard targetPID == ownPID else {
                esAPI.respondAuthResult(esClient, message, ES_AUTH_RESULT_ALLOW, true)
                esAPI.releaseMessage(message)
                return
            }

            let sourceProcess = message.pointee.process
            let sourceToken = sourceProcess.pointee.audit_token
            let sourcePID = pid_t(sourceToken.val.5)

            let eventTypeName = esEventTypeName(message.pointee.event_type)

            if sourcePID == ownPID || sourcePID == ownParentPID {
                if isTrustedBySignature(sourceProcess) {
                    esAPI.respondAuthResult(esClient, message, ES_AUTH_RESULT_ALLOW, true)
                } else {
                    let sourcePIDVersion = sourceToken.val.6
                    let signingID = esString(sourceProcess.pointee.signing_id)
                    let teamID = sourceProcess.pointee.is_platform_binary ? "apple" : esString(sourceProcess.pointee.team_id)
                    logger.fault("Blocking spoofed expected source (event: \(message.pointee.event_type.rawValue, privacy: .public), PID \(sourcePID, privacy: .public) version \(sourcePIDVersion, privacy: .public), signingID: \(signingID, privacy: .public), teamID: \(teamID, privacy: .public))")
                    esAPI.respondAuthResult(esClient, message, ES_AUTH_RESULT_DENY, false)
                    onTamperDenied?(TamperAttemptEvent(
                        sourcePID: sourcePID,
                        sourcePIDVersion: UInt32(sourcePIDVersion),
                        teamID: teamID,
                        signingID: signingID,
                        esEventType: eventTypeName
                    ))
                }
            } else {
                let sourcePIDVersion = sourceToken.val.6
                let signingID = esString(sourceProcess.pointee.signing_id)
                let teamID = sourceProcess.pointee.is_platform_binary ? "apple" : esString(sourceProcess.pointee.team_id)
                logger.fault("Preventing tamper attempt against opfilter (event: \(message.pointee.event_type.rawValue, privacy: .public), from PID \(sourcePID, privacy: .public) version \(sourcePIDVersion, privacy: .public), signingID: \(signingID, privacy: .public), teamID: \(teamID, privacy: .public))")
                esAPI.respondAuthResult(esClient, message, ES_AUTH_RESULT_DENY, false)
                onTamperDenied?(TamperAttemptEvent(
                    sourcePID: sourcePID,
                    sourcePIDVersion: UInt32(sourcePIDVersion),
                    teamID: teamID,
                    signingID: signingID,
                    esEventType: eventTypeName
                ))
            }
            esAPI.releaseMessage(message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let newClient else {
            logger.fault("ESTamperResistanceAdapter: failed to create ES client (\(result.rawValue, privacy: .public))")
            exit(EXIT_FAILURE)
        }

        client = newClient

        guard esAPI.subscribe(newClient, to: [
            ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME,
            ES_EVENT_TYPE_AUTH_SIGNAL,
        ]) == ES_RETURN_SUCCESS else {
            logger.fault("ESTamperResistanceAdapter: failed to subscribe to ES events")
            exit(EXIT_FAILURE)
        }
    }
}
