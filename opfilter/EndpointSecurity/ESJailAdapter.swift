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
//  Process identity key: (pid, pidVersion)
//  pidVersion increments on exec AND on fork (for the child). Using the full
//  audit token identity rather than just the PID prevents false inheritance
//  when a PID is reused after exit and protects against daemon()-style
//  double-fork patterns where the supervising intermediate process exits
//  quickly. Each (pid, pidVersion) pair uniquely identifies one process
//  image for the lifetime of the system.
//
//  Lifecycle:
//  • FORK  → onFork. If the parent key is in the jailed set the child
//    inherits the same rule. Otherwise a direct signing-ID check is done.
//  • EXEC  → onExec. The pre-exec token is atomically replaced with the
//    post-exec token so the process stays jailed across exec boundaries.
//  • EXIT  → onProcessExited. The (pid, pidVersion) key is removed and
//    the audit token is unmuted. Children that inherited the jail keep
//    their own entries and remain jailed (orphan-safe).
//

import Foundation
import EndpointSecurity
import Security
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "es-jail-adapter")

// MARK: - ProcessKey

/// Composite identity key for a jailed process.
/// Using (pid, pidVersion) rather than pid alone prevents false inheritance
/// when a PID is reused after its previous occupant exits.
private struct ProcessKey: Hashable {
    let pid: pid_t
    let pidVersion: UInt32

    init(_ token: audit_token_t) {
        self.pid = pid_t(bitPattern: token.val.5)
        self.pidVersion = token.val.7
    }
}

// MARK: - ESJailAdapter

final class ESJailAdapter {
    private let interactor: FilterInteractor
    private var client: OpaquePointer?
    private let rulesLock = OSAllocatedUnfairLock(initialState: [JailRule]())
    /// Maps each jailed process's (pid, pidVersion) to the jail rule ID that
    /// covers it. Populated for direct signature matches and inherited
    /// descendants. Each entry is independent — a child's entry survives its
    /// parent's exit, so orphaned processes remain correctly jailed.
    private let jailedProcessesLock = OSAllocatedUnfairLock(initialState: [ProcessKey: UUID]())

    init(interactor: FilterInteractor) {
        self.interactor = interactor
    }

    // MARK: - Startup

    func start(initialRules: [JailRule]) {
        let interactor = self.interactor
        let jailedProcessesLock = self.jailedProcessesLock

        let result = es_new_client(&client) { esClient, message in
            let key = ProcessKey(message.pointee.process.pointee.audit_token)
            guard let ruleID = jailedProcessesLock.withLock({ $0[key] }) else {
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
        let parentKey = ProcessKey(parentToken)

        // Inherit jail from parent if it is currently tracked.
        if let parentRuleID = jailedProcessesLock.withLock({ $0[parentKey] }) {
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

    /// Called on NOTIFY_EXEC with both the pre-exec and post-exec audit tokens.
    /// `message.pointee.process` holds the pre-exec token; `exec.target` holds
    /// the post-exec token. pidVersion increments on exec, so the old key must
    /// be atomically replaced with the new one to keep the jail in effect.
    func onExec(oldToken: audit_token_t, newToken: audit_token_t, teamID: String, signingID: String, parentToken: audit_token_t) {
        let oldKey = ProcessKey(oldToken)
        let newKey = ProcessKey(newToken)
        let parentKey = ProcessKey(parentToken)

        let inheritedRuleID = jailedProcessesLock.withLock { map -> UUID? in
            // Check 1: pre-exec self was jailed → swap keys.
            if let ruleID = map[oldKey] {
                map.removeValue(forKey: oldKey)
                map[newKey] = ruleID
                return ruleID
            }
            // Check 2: parent process is jailed → inherit.
            if let ruleID = map[parentKey] {
                map[newKey] = ruleID
                return ruleID
            }
            return nil
        }

        if let ruleID = inheritedRuleID {
            guard let client else { return }
            var t = newToken
            es_mute_process(client, &t)
            logger.debug("ESJailAdapter: muted exec'd process pid=\(newKey.pid) pidVersion=\(newKey.pidVersion) signingID=\(signingID, privacy: .public)")
            return
        }

        // Not inherited — check direct signing-ID match on new image.
        let rules = rulesLock.withLock { $0 }
        guard !rules.isEmpty else { return }
        let resolvedTeamID = teamID.isEmpty ? appleTeamID : teamID
        guard let rule = rules.first(where: { $0.jailedSignature.matches(resolvedTeamID: resolvedTeamID, signingID: signingID) }) else { return }
        mute(newToken, ruleID: rule.id, signingID: signingID)
    }

    func onProcessExited(auditToken: audit_token_t) {
        let key = ProcessKey(auditToken)
        jailedProcessesLock.withLock { $0.removeValue(forKey: key) }
        guard let client else { return }
        var token = auditToken
        es_unmute_process(client, &token)
    }

    // MARK: - Private helpers

    private func mute(_ token: audit_token_t, ruleID: UUID, signingID: String) {
        guard let client else { return }
        let key = ProcessKey(token)
        jailedProcessesLock.withLock { $0[key] = ruleID }
        var t = token
        es_mute_process(client, &t)
        logger.debug("ESJailAdapter: muted process pid=\(key.pid) pidVersion=\(key.pidVersion) signingID=\(signingID, privacy: .public)")
    }
}
