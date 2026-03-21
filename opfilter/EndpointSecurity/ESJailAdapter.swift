//
//  ESJailAdapter.swift
//  opfilter
//
//  A dedicated ES client for App Jail enforcement. Jail rules restrict a
//  process to only a specified set of path prefixes; any file access outside
//  those prefixes is denied.
//
//  This client subscribes to both lifecycle events (FORK, EXEC, EXIT) and file
//  auth events. Lifecycle events drive the jailed-process tracking map; file
//  auth events are evaluated against jail policy for tracked processes and
//  immediately allowed for all others.
//
//  Fully isolated from the main ESInboundAdapter client — no audit tokens are
//  shared between the two ES clients.
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
//  * FORK  -> If the parent key is in the jailed set the child
//    inherits the same rule. Otherwise a direct signing-ID check is done.
//  * EXEC  -> The pre-exec token is atomically replaced with the
//    post-exec token so the process stays jailed across exec boundaries.
//  * EXIT  -> The (pid, pidVersion) key is removed. Children that inherited
//    the jail keep their own entries and remain jailed (orphan-safe).
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
        let rulesLock = self.rulesLock

        let result = es_new_client(&client) { esClient, message in
            switch message.pointee.event_type {

            // --- Lifecycle events ---

            case ES_EVENT_TYPE_NOTIFY_FORK:
                let parentKey = ProcessKey(message.pointee.process.pointee.audit_token)
                let child = message.pointee.event.fork.child.pointee
                let signingID = ESInboundAdapter.string(from: child.signing_id)

                if let parentRuleID = jailedProcessesLock.withLock({ $0[parentKey] }) {
                    let childKey = ProcessKey(child.audit_token)
                    jailedProcessesLock.withLock { $0[childKey] = parentRuleID }
                    logger.debug("ESJailAdapter: jailed forked child pid=\(childKey.pid) pidVersion=\(childKey.pidVersion) signingID=\(signingID, privacy: .public) (inherited)")
                    return
                }

                let rules = rulesLock.withLock { $0 }
                guard !rules.isEmpty else { return }
                let teamID = ESInboundAdapter.string(from: child.team_id)
                let resolvedTeamID = teamID.isEmpty ? appleTeamID : teamID
                guard let rule = rules.first(where: { $0.jailedSignature.matches(resolvedTeamID: resolvedTeamID, signingID: signingID) }) else { return }
                let childKey = ProcessKey(child.audit_token)
                jailedProcessesLock.withLock { $0[childKey] = rule.id }
                logger.debug("ESJailAdapter: jailed forked child pid=\(childKey.pid) pidVersion=\(childKey.pidVersion) signingID=\(signingID, privacy: .public) (direct match)")

            case ES_EVENT_TYPE_AUTH_EXEC:
                let oldKey = ProcessKey(message.pointee.process.pointee.audit_token)
                let target = message.pointee.event.exec.target.pointee
                let newKey = ProcessKey(target.audit_token)
                let signingID = ESInboundAdapter.string(from: target.signing_id)

                let inheritedRuleID = jailedProcessesLock.withLock { map -> UUID? in
                    if let ruleID = map[oldKey] {
                        map.removeValue(forKey: oldKey)
                        map[newKey] = ruleID
                        return ruleID
                    }
                    let parentKey = ProcessKey(message.pointee.process.pointee.parent_audit_token)
                    if let ruleID = map[parentKey] {
                        map[newKey] = ruleID
                        return ruleID
                    }
                    return nil
                }

                if inheritedRuleID != nil {
                    logger.debug("ESJailAdapter: jailed exec'd process pid=\(newKey.pid) pidVersion=\(newKey.pidVersion) signingID=\(signingID, privacy: .public) (inherited)")
                    es_respond_auth_result(esClient, message, ES_AUTH_RESULT_ALLOW, false)
                    return
                }

                let rules = rulesLock.withLock { $0 }
                if !rules.isEmpty {
                    let teamID = ESInboundAdapter.string(from: target.team_id)
                    let resolvedTeamID = teamID.isEmpty ? appleTeamID : teamID
                    if let rule = rules.first(where: { $0.jailedSignature.matches(resolvedTeamID: resolvedTeamID, signingID: signingID) }) {
                        jailedProcessesLock.withLock { $0[newKey] = rule.id }
                        logger.debug("ESJailAdapter: jailed exec'd process pid=\(newKey.pid) pidVersion=\(newKey.pidVersion) signingID=\(signingID, privacy: .public) (direct match)")
                    }
                }

                es_respond_auth_result(esClient, message, ES_AUTH_RESULT_ALLOW, false)

            case ES_EVENT_TYPE_NOTIFY_EXIT:
                let key = ProcessKey(message.pointee.process.pointee.audit_token)
                _ = jailedProcessesLock.withLock { $0.removeValue(forKey: key) }

            // --- File auth events (only enforced for jailed processes) ---

            case ES_EVENT_TYPE_AUTH_OPEN,
                 ES_EVENT_TYPE_AUTH_RENAME,
                 ES_EVENT_TYPE_AUTH_UNLINK,
                 ES_EVENT_TYPE_AUTH_LINK,
                 ES_EVENT_TYPE_AUTH_CREATE,
                 ES_EVENT_TYPE_AUTH_TRUNCATE,
                 ES_EVENT_TYPE_AUTH_COPYFILE,
                 ES_EVENT_TYPE_AUTH_READDIR,
                 ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
                 ES_EVENT_TYPE_AUTH_CLONE:
                let key = ProcessKey(message.pointee.process.pointee.audit_token)
                guard let ruleID = jailedProcessesLock.withLock({ $0[key] }) else {
                    switch message.pointee.event_type {
                    case ES_EVENT_TYPE_AUTH_OPEN:
                        es_respond_flags_result(esClient, message, UInt32(message.pointee.event.open.fflag), false)
                    case ES_EVENT_TYPE_AUTH_RENAME,
                         ES_EVENT_TYPE_AUTH_UNLINK,
                         ES_EVENT_TYPE_AUTH_LINK,
                         ES_EVENT_TYPE_AUTH_CREATE,
                         ES_EVENT_TYPE_AUTH_TRUNCATE,
                         ES_EVENT_TYPE_AUTH_COPYFILE,
                         ES_EVENT_TYPE_AUTH_READDIR,
                         ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
                         ES_EVENT_TYPE_AUTH_CLONE:
                        es_respond_auth_result(esClient, message, ES_AUTH_RESULT_ALLOW, false)
                    default:
                        fatalError("ESJailAdapter: received unsubscribed event type \(message.pointee.event_type.rawValue)")
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

            default:
                fatalError("ESJailAdapter: received unsubscribed event type \(message.pointee.event_type.rawValue)")
            }
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            logger.fault("ESJailAdapter: failed to create ES client: \(result.rawValue)")
            exit(EXIT_FAILURE)
        }

        let eventTypes: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT,
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
        guard es_subscribe(client!, eventTypes, UInt32(eventTypes.count)) == ES_RETURN_SUCCESS else {
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
}
