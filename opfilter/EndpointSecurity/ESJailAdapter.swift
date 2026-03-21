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
//  • When the main client observes NOTIFY_FORK / NOTIFY_EXEC for a process
//    whose signing ID matches a jail rule, it calls onProcessStarted.
//  • When the main client observes NOTIFY_EXIT, it calls onProcessExited.
//  • When jail rules change, updateJailRules re-enumerates running processes
//    and mutes any whose signing ID now matches.
//

import Foundation
import EndpointSecurity
import Security
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "es-jail-adapter")

// audit_token_for_pid is in libBSM (always loaded on macOS) but is not
// directly bridged into Swift modules, so we locate it at runtime via dlsym.
private typealias AuditTokenForPID = @convention(c) (pid_t, UnsafeMutablePointer<audit_token_t>) -> Int32
private let _auditTokenForPID: AuditTokenForPID? = {
    guard let sym = dlsym(RTLD_DEFAULT, "audit_token_for_pid") else { return nil }
    return unsafeBitCast(sym, to: AuditTokenForPID.self)
}()

private func auditToken(forPID pid: pid_t) -> audit_token_t? {
    guard let fn = _auditTokenForPID else { return nil }
    var token = audit_token_t()
    guard fn(pid, &token) == 0 else { return nil }
    return token
}

// MARK: - ESJailAdapter

final class ESJailAdapter {
    private let interactor: FilterInteractor
    private var client: OpaquePointer?
    private let rulesLock = OSAllocatedUnfairLock(initialState: [JailRule]())

    init(interactor: FilterInteractor) {
        self.interactor = interactor
    }

    // MARK: - Startup

    func start(initialRules: [JailRule]) {
        let interactor = self.interactor
        let result = es_new_client(&client) { esClient, message in
            switch message.pointee.event_type {
            case ES_EVENT_TYPE_AUTH_OPEN where message.pointee.event.open.file.pointee.path.data == nil:
                es_respond_flags_result(esClient, message, UInt32(message.pointee.event.open.fflag), false)
            case ES_EVENT_TYPE_AUTH_OPEN:
                interactor.handle(.fileAuth(ESInboundAdapter.openFileEvent(from: message, esClient: esClient)))
            case ES_EVENT_TYPE_AUTH_RENAME:
                let path = ESInboundAdapter.string(from: message.pointee.event.rename.source.pointee.path)
                interactor.handle(.fileAuth(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .rename, path: path)))
            case ES_EVENT_TYPE_AUTH_UNLINK:
                let path = ESInboundAdapter.string(from: message.pointee.event.unlink.target.pointee.path)
                interactor.handle(.fileAuth(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .unlink, path: path)))
            case ES_EVENT_TYPE_AUTH_LINK:
                let path = ESInboundAdapter.string(from: message.pointee.event.link.source.pointee.path)
                interactor.handle(.fileAuth(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .link, path: path)))
            case ES_EVENT_TYPE_AUTH_CREATE:
                let path = ESInboundAdapter.createEventPath(from: message.pointee.event.create)
                interactor.handle(.fileAuth(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .create, path: path)))
            case ES_EVENT_TYPE_AUTH_TRUNCATE:
                let path = ESInboundAdapter.string(from: message.pointee.event.truncate.target.pointee.path)
                interactor.handle(.fileAuth(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .truncate, path: path)))
            case ES_EVENT_TYPE_AUTH_COPYFILE:
                let path = ESInboundAdapter.string(from: message.pointee.event.copyfile.source.pointee.path)
                interactor.handle(.fileAuth(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .copyfile, path: path)))
            case ES_EVENT_TYPE_AUTH_READDIR:
                let path = ESInboundAdapter.string(from: message.pointee.event.readdir.target.pointee.path)
                interactor.handle(.fileAuth(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .readdir, path: path)))
            case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
                let path = ESInboundAdapter.string(from: message.pointee.event.exchangedata.file1.pointee.path)
                interactor.handle(.fileAuth(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .exchangedata, path: path)))
            case ES_EVENT_TYPE_AUTH_CLONE:
                let path = ESInboundAdapter.string(from: message.pointee.event.clone.source.pointee.path)
                interactor.handle(.fileAuth(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .clone, path: path)))
            default:
                fatalError("ESJailAdapter: received unsubscribed event type \(message.pointee.event_type.rawValue)")
            }
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            logger.fault("ESJailAdapter: failed to create ES client: \(result.rawValue)")
            exit(EXIT_FAILURE)
        }

        // Inverted process muting: the client only receives events for processes
        // whose audit tokens have been explicitly muted via es_mute_process.
        // By default (no muted tokens) the client receives nothing — zero overhead
        // when no jail rules are configured.
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
        muteMatchingRunningProcesses(rules: initialRules)
        logger.info("ESJailAdapter: started with \(initialRules.count) initial jail rule(s)")
    }

    // MARK: - Rule updates

    func updateJailRules(_ rules: [JailRule]) {
        rulesLock.withLock { $0 = rules }
        muteMatchingRunningProcesses(rules: rules)
        logger.info("ESJailAdapter: jail rules updated — \(rules.count) rule(s)")
    }

    // MARK: - Process lifecycle (forwarded from main ES client)

    func onProcessStarted(auditToken: audit_token_t, teamID: String, signingID: String) {
        let rules = rulesLock.withLock { $0 }
        guard !rules.isEmpty else { return }
        let resolvedTeamID = teamID.isEmpty ? appleTeamID : teamID
        guard rules.contains(where: { $0.jailedSignature.matches(resolvedTeamID: resolvedTeamID, signingID: signingID) }) else { return }
        guard let client else { return }
        var token = auditToken
        es_mute_process(client, &token)
        logger.debug("ESJailAdapter: muted process signingID=\(signingID, privacy: .public)")
    }

    func onProcessExited(auditToken: audit_token_t) {
        guard let client else { return }
        var token = auditToken
        es_unmute_process(client, &token)
    }

    // MARK: - Private helpers

    private func muteMatchingRunningProcesses(rules: [JailRule]) {
        guard let client, !rules.isEmpty else { return }
        let processes = ProcessEnumerator.enumerateAll()
        for proc in processes {
            let resolvedTeamID = proc.teamID.isEmpty ? appleTeamID : proc.teamID
            guard rules.contains(where: { $0.jailedSignature.matches(resolvedTeamID: resolvedTeamID, signingID: proc.signingID) }) else { continue }
            guard let token = auditToken(forPID: pid_t(proc.pid)) else { continue }
            var mutableToken = token
            es_mute_process(client, &mutableToken)
            logger.debug("ESJailAdapter: muted running process pid=\(proc.pid) signingID=\(proc.signingID, privacy: .public)")
        }
    }
}
