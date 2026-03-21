//
//  ESJailAdapter.swift
//  opfilter
//
//  A dedicated ES client for App Jail enforcement. Jail rules restrict a
//  process to only a specified set of path prefixes; any file access outside
//  those prefixes is denied.
//
//  ES muting strategy: inverted process muting.
//  es_invert_muting(client, ES_MUTE_INVERSION_TYPE_PROCESS) makes the kernel
//  deliver events only for processes whose audit tokens have been explicitly
//  muted via es_mute_process. This avoids receiving file events for the entire
//  system — only jailed processes generate events on this client.
//
//  Lifecycle:
//  • When the main client observes NOTIFY_FORK, it calls onFork. If the
//    parent is already jailed the child inherits the same jail rule.
//  • When the main client observes NOTIFY_EXEC, it calls onExec. If the
//    process was already jailed (e.g., by ancestry) the new image is
//    re-muted with its updated audit token.
//  • When the main client observes NOTIFY_EXIT, it calls onProcessExited.
//
//  Orphaned processes (jailed processes whose parent exits before them) are
//  not currently tracked; their jail enforcement continues until they exit.
//

import Foundation
import EndpointSecurity
import Security
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "es-jail-adapter")

// MARK: - ESJailAdapter

final class ESJailAdapter {
    private let interactor: FilterInteractor
    private var client: OpaquePointer?
    private let rulesLock = OSAllocatedUnfairLock(initialState: [JailRule]())
    /// Maps each jailed process's PID to the jail rule ID that covers it.
    /// Populated for both direct matches (signing ID matches a rule) and
    /// inherited jails (child of a jailed process).
    private let jailedPIDsLock = OSAllocatedUnfairLock(initialState: [pid_t: UUID]())

    init(interactor: FilterInteractor) {
        self.interactor = interactor
    }

    // MARK: - Startup

    func start(initialRules: [JailRule]) {
        let interactor = self.interactor
        let jailedPIDsLock = self.jailedPIDsLock

        let result = es_new_client(&client) { esClient, message in
            let pid = pid_t(message.pointee.process.pointee.audit_token.val.5)
            guard let ruleID = jailedPIDsLock.withLock({ $0[pid] }) else {
                // Process is muted but not in our tracking — stale state, allow.
                switch message.pointee.event_type {
                case ES_EVENT_TYPE_AUTH_OPEN:
                    es_respond_flags_result(esClient, message, UInt32(message.pointee.event.open.fflag), false)
                default:
                    es_respond_auth_result(esClient, message, ES_AUTH_RESULT_ALLOW, false)
                }
                return
            }

            switch message.pointee.event_type {
            case ES_EVENT_TYPE_AUTH_OPEN where message.pointee.event.open.file.pointee.path.data == nil:
                es_respond_flags_result(esClient, message, UInt32(message.pointee.event.open.fflag), false)
            case ES_EVENT_TYPE_AUTH_OPEN:
                interactor.handleJailEventSync(ESInboundAdapter.openFileEvent(from: message, esClient: esClient), jailRuleID: ruleID)
            case ES_EVENT_TYPE_AUTH_RENAME:
                let path = ESInboundAdapter.string(from: message.pointee.event.rename.source.pointee.path)
                interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .rename, path: path), jailRuleID: ruleID)
            case ES_EVENT_TYPE_AUTH_UNLINK:
                let path = ESInboundAdapter.string(from: message.pointee.event.unlink.target.pointee.path)
                interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .unlink, path: path), jailRuleID: ruleID)
            case ES_EVENT_TYPE_AUTH_LINK:
                let path = ESInboundAdapter.string(from: message.pointee.event.link.source.pointee.path)
                interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .link, path: path), jailRuleID: ruleID)
            case ES_EVENT_TYPE_AUTH_CREATE:
                let path = ESInboundAdapter.createEventPath(from: message.pointee.event.create)
                interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .create, path: path), jailRuleID: ruleID)
            case ES_EVENT_TYPE_AUTH_TRUNCATE:
                let path = ESInboundAdapter.string(from: message.pointee.event.truncate.target.pointee.path)
                interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .truncate, path: path), jailRuleID: ruleID)
            case ES_EVENT_TYPE_AUTH_COPYFILE:
                let path = ESInboundAdapter.string(from: message.pointee.event.copyfile.source.pointee.path)
                interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .copyfile, path: path), jailRuleID: ruleID)
            case ES_EVENT_TYPE_AUTH_READDIR:
                let path = ESInboundAdapter.string(from: message.pointee.event.readdir.target.pointee.path)
                interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .readdir, path: path), jailRuleID: ruleID)
            case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
                let path = ESInboundAdapter.string(from: message.pointee.event.exchangedata.file1.pointee.path)
                interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .exchangedata, path: path), jailRuleID: ruleID)
            case ES_EVENT_TYPE_AUTH_CLONE:
                let path = ESInboundAdapter.string(from: message.pointee.event.clone.source.pointee.path)
                interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .clone, path: path), jailRuleID: ruleID)
            default:
                fatalError("ESJailAdapter: received unsubscribed event type \(message.pointee.event_type.rawValue)")
            }
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            logger.fault("ESJailAdapter: failed to create ES client: \(result.rawValue)")
            exit(EXIT_FAILURE)
        }

        es_invert_muting(client!, ES_MUTE_INVERSION_TYPE_PROCESS)

        let authEventTypes: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_LINK,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_TRUNCATE,
            ES_EVENT_TYPE_AUTH_COPYFILE,
            ES_EVENT_TYPE_AUTH_READDIR,
            ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
            ES_EVENT_TYPE_AUTH_CLONE,
        ]
        guard es_subscribe(client!, authEventTypes, UInt32(authEventTypes.count)) == ES_RETURN_SUCCESS else {
            logger.fault("ESJailAdapter: failed to subscribe to ES events")
            exit(EXIT_FAILURE)
        }

        rulesLock.withLock { $0 = initialRules }
        logger.info("ESJailAdapter: started with \(initialRules.count) initial jail rule(s)")
    }

    // MARK: - Rule updates

    func updateJailRules(_ rules: [JailRule]) {
        rulesLock.withLock { $0 = rules }
        logger.info("ESJailAdapter: jail rules updated — \(rules.count) rule(s)")
    }

    // MARK: - Process lifecycle (forwarded from main ES client)

    func onFork(childToken: audit_token_t, teamID: String, signingID: String, parentToken: audit_token_t) {
        let parentPID = pid_t(parentToken.val.5)

        // Inherit jail from parent if it is currently jailed.
        if let parentRuleID = jailedPIDsLock.withLock({ $0[parentPID] }) {
            mute(childToken, ruleID: parentRuleID, signingID: signingID)
            return
        }

        // Otherwise check for a direct signing-ID match.
        let rules = rulesLock.withLock { $0 }
        guard !rules.isEmpty else { return }
        let resolvedTeamID = teamID.isEmpty ? appleTeamID : teamID
        guard let rule = rules.first(where: { $0.jailedSignature.matches(resolvedTeamID: resolvedTeamID, signingID: signingID) }) else { return }
        mute(childToken, ruleID: rule.id, signingID: signingID)
    }

    func onExec(newToken: audit_token_t, teamID: String, signingID: String) {
        let pid = pid_t(newToken.val.5)

        // If the process was already jailed, re-mute with the new token.
        // The audit token's pidVersion increments on exec so the old mute
        // may no longer match; re-issuing ensures the jail stays in effect.
        if let existingRuleID = jailedPIDsLock.withLock({ $0[pid] }) {
            guard let client else { return }
            var t = newToken
            es_mute_process(client, &t)
            logger.debug("ESJailAdapter: re-muted exec'd process pid=\(pid) signingID=\(signingID, privacy: .public)")
            return
        }

        // New process image — check for a direct signing-ID match.
        let rules = rulesLock.withLock { $0 }
        guard !rules.isEmpty else { return }
        let resolvedTeamID = teamID.isEmpty ? appleTeamID : teamID
        guard let rule = rules.first(where: { $0.jailedSignature.matches(resolvedTeamID: resolvedTeamID, signingID: signingID) }) else { return }
        mute(newToken, ruleID: rule.id, signingID: signingID)
    }

    func onProcessExited(auditToken: audit_token_t) {
        let pid = pid_t(auditToken.val.5)
        jailedPIDsLock.withLock { $0.removeValue(forKey: pid) }
        guard let client else { return }
        var token = auditToken
        es_unmute_process(client, &token)
    }

    // MARK: - Private helpers

    private func mute(_ token: audit_token_t, ruleID: UUID, signingID: String) {
        guard let client else { return }
        let pid = pid_t(token.val.5)
        jailedPIDsLock.withLock { $0[pid] = ruleID }
        var t = token
        es_mute_process(client, &t)
        logger.debug("ESJailAdapter: muted process pid=\(pid) signingID=\(signingID, privacy: .public)")
    }
}
