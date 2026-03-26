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

    init(pid: pid_t, pidVersion: UInt32) {
        self.pid = pid
        self.pidVersion = pidVersion
    }
}

// MARK: - ESJailAdapter

final class ESJailAdapter {
    private let interactor: FilterInteractor
    private let processTree: ProcessTreeProtocol
    private let esJailAdapterQueue: DispatchQueue
    private let jailSweepQueue: DispatchQueue
    private let jailCascadeQueue: DispatchQueue
    private var client: OpaquePointer?
    private var sweepTimer: DispatchSourceTimer?
    private let rulesLock = OSAllocatedUnfairLock(initialState: [JailRule]())
    /// Maps each jailed process's (pid, pidVersion) to the jail rule ID that
    /// covers it. Populated for direct signature matches and inherited
    /// descendants. Each entry is independent — a child's entry survives its
    /// parent's exit, so orphaned processes remain correctly jailed.
    private let jailedProcessesLock = OSAllocatedUnfairLock(initialState: [ProcessKey: UUID]())
    private let jailCacheProcessor = JailFileAccessEventCacheDecisionProcessor()

    init(
        interactor: FilterInteractor,
        processTree: ProcessTreeProtocol,
        esJailAdapterQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.es-jail-adapter", qos: .userInteractive),
        jailSweepQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.jail-sweep", qos: .background),
        jailCascadeQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.jail-cascade", qos: .background, attributes: .concurrent)
    ) {
        self.interactor = interactor
        self.processTree = processTree
        self.esJailAdapterQueue = esJailAdapterQueue
        self.jailSweepQueue = jailSweepQueue
        self.jailCascadeQueue = jailCascadeQueue
    }

    // MARK: - Startup

    func start(initialRules: [JailRule]) {
        guard client == nil else {
            logger.warning("ESJailAdapter: already started — updating rules only")
            rulesLock.withLock { $0 = initialRules }
            return
        }

        let interactor = self.interactor
        let esJailAdapterQueue = self.esJailAdapterQueue
        let jailedProcessesLock = self.jailedProcessesLock
        let rulesLock = self.rulesLock
        let jailCacheProcessor = self.jailCacheProcessor

        let result = es_new_client(&client) { esClient, message in
            let correlationID = UUID()

            switch message.pointee.event_type {

            // --- Lifecycle events: extract synchronously, dispatch with extracted values ---

            case ES_EVENT_TYPE_NOTIFY_FORK:
                let parentKey = ProcessKey(message.pointee.process.pointee.audit_token)
                let child = message.pointee.event.fork.child.pointee
                let childKey = ProcessKey(child.audit_token)
                let signingID = ESInboundAdapter.string(from: child.signing_id)
                let teamID = ESInboundAdapter.string(from: child.team_id)
                esJailAdapterQueue.async {
                    if let parentRuleID = jailedProcessesLock.withLock({ $0[parentKey] }) {
                        jailedProcessesLock.withLock { $0[childKey] = parentRuleID }
                        return
                    }
                    let rules = rulesLock.withLock { $0 }
                    guard !rules.isEmpty else { return }
                    let resolvedTeamID = teamID.isEmpty ? appleTeamID : teamID
                    guard let rule = rules.first(where: { $0.jailedSignature.matches(resolvedTeamID: resolvedTeamID, signingID: signingID) }) else { return }
                    jailedProcessesLock.withLock { $0[childKey] = rule.id }
                }

            case ES_EVENT_TYPE_NOTIFY_EXEC:
                let oldKey = ProcessKey(message.pointee.process.pointee.audit_token)
                let target = message.pointee.event.exec.target.pointee
                let newKey = ProcessKey(target.audit_token)
                let parentKey = ProcessKey(message.pointee.process.pointee.parent_audit_token)
                let signingID = ESInboundAdapter.string(from: target.signing_id)
                let teamID = ESInboundAdapter.string(from: target.team_id)
                esJailAdapterQueue.async {
                    let inherited = jailedProcessesLock.withLock { map -> Bool in
                        if let ruleID = map[oldKey] {
                            map.removeValue(forKey: oldKey)
                            map[newKey] = ruleID
                            return true
                        }
                        if let ruleID = map[parentKey] {
                            map[newKey] = ruleID
                            return true
                        }
                        return false
                    }
                    guard !inherited else { return }
                    let rules = rulesLock.withLock { $0 }
                    guard !rules.isEmpty else { return }
                    let resolvedTeamID = teamID.isEmpty ? appleTeamID : teamID
                    if let rule = rules.first(where: { $0.jailedSignature.matches(resolvedTeamID: resolvedTeamID, signingID: signingID) }) {
                        jailedProcessesLock.withLock { $0[newKey] = rule.id }
                    }
                }

            case ES_EVENT_TYPE_NOTIFY_EXIT:
                let key = ProcessKey(message.pointee.process.pointee.audit_token)
                esJailAdapterQueue.async {
                    _ = jailedProcessesLock.withLock { $0.removeValue(forKey: key) }
                }

            // --- File auth events: retain, dispatch, release in all response paths ---

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
                es_retain_message(message)
                esJailAdapterQueue.async {
                    let key = ProcessKey(message.pointee.process.pointee.audit_token)
                    guard let ruleID = jailedProcessesLock.withLock({ $0[key] }) else {
                        let nonJailedCache = jailCacheProcessor.decide(jailsConfigured: !rulesLock.withLock({ $0 }).isEmpty).shouldCache
                        switch message.pointee.event_type {
                        case ES_EVENT_TYPE_AUTH_OPEN:
                            es_respond_flags_result(esClient, message, UInt32.max, nonJailedCache)
                        default:
                            es_respond_auth_result(esClient, message, ES_AUTH_RESULT_ALLOW, nonJailedCache)
                        }
                        es_release_message(message)
                        return
                    }

                    switch message.pointee.event_type {
                    case ES_EVENT_TYPE_AUTH_OPEN where message.pointee.event.open.file.pointee.path.data == nil:
                        es_respond_flags_result(esClient, message, UInt32(message.pointee.event.open.fflag), false)
                        es_release_message(message)
                    case ES_EVENT_TYPE_AUTH_OPEN:
                        interactor.handleJailEventSync(ESInboundAdapter.openFileEvent(from: message, esClient: esClient, correlationID: correlationID), jailRuleID: ruleID)
                    case ES_EVENT_TYPE_AUTH_RENAME:
                        let path = ESInboundAdapter.string(from: message.pointee.event.rename.source.pointee.path)
                        interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .rename, path: path, correlationID: correlationID), jailRuleID: ruleID)
                    case ES_EVENT_TYPE_AUTH_UNLINK:
                        let path = ESInboundAdapter.string(from: message.pointee.event.unlink.target.pointee.path)
                        interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .unlink, path: path, correlationID: correlationID), jailRuleID: ruleID)
                    case ES_EVENT_TYPE_AUTH_LINK:
                        let path = ESInboundAdapter.string(from: message.pointee.event.link.source.pointee.path)
                        interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .link, path: path, correlationID: correlationID), jailRuleID: ruleID)
                    case ES_EVENT_TYPE_AUTH_CREATE:
                        let path = ESInboundAdapter.createEventPath(from: message.pointee.event.create)
                        interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .create, path: path, correlationID: correlationID), jailRuleID: ruleID)
                    case ES_EVENT_TYPE_AUTH_TRUNCATE:
                        let path = ESInboundAdapter.string(from: message.pointee.event.truncate.target.pointee.path)
                        interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .truncate, path: path, correlationID: correlationID), jailRuleID: ruleID)
                    case ES_EVENT_TYPE_AUTH_COPYFILE:
                        let path = ESInboundAdapter.string(from: message.pointee.event.copyfile.source.pointee.path)
                        interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .copyfile, path: path, correlationID: correlationID), jailRuleID: ruleID)
                    case ES_EVENT_TYPE_AUTH_READDIR:
                        let path = ESInboundAdapter.string(from: message.pointee.event.readdir.target.pointee.path)
                        interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .readdir, path: path, correlationID: correlationID), jailRuleID: ruleID)
                    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
                        let path = ESInboundAdapter.string(from: message.pointee.event.exchangedata.file1.pointee.path)
                        interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .exchangedata, path: path, correlationID: correlationID), jailRuleID: ruleID)
                    case ES_EVENT_TYPE_AUTH_CLONE:
                        let path = ESInboundAdapter.string(from: message.pointee.event.clone.source.pointee.path)
                        interactor.handleJailEventSync(ESInboundAdapter.fileAuthEvent(from: message, esClient: esClient, operation: .clone, path: path, correlationID: correlationID), jailRuleID: ruleID)
                    default:
                        fatalError("ESJailAdapter: received unsubscribed event type \(message.pointee.event_type.rawValue)")
                    }
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
            ES_EVENT_TYPE_NOTIFY_EXEC,
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
    }

    // MARK: - Lifecycle

    func stop() {
        sweepTimer?.cancel()
        sweepTimer = nil
        guard let client else { return }
        es_delete_client(client)
        self.client = nil
        jailedProcessesLock.withLock { $0.removeAll() }
    }

    // MARK: - Rule updates

    func updateJailRules(_ rules: [JailRule]) {
        rulesLock.withLock { $0 = rules }
        if let client {
            es_clear_cache(client)
        }
    }

    func activeJailedPIDs() -> Set<pid_t> {
        jailedProcessesLock.withLock { Set($0.keys.map(\.pid)) }
    }

    // MARK: - Sweep

    func startSweepTimer() {
        let timer = DispatchSource.makeTimerSource(queue: jailSweepQueue)
        timer.schedule(deadline: .now() + .seconds(10), repeating: .seconds(10))
        timer.setEventHandler { [weak self] in self?.sweepJailedProcesses() }
        timer.resume()
        sweepTimer = timer
    }

    private func sweepJailedProcesses() {
        let rules = rulesLock.withLock { $0 }
        guard !rules.isEmpty else { return }

        let allRecords = processTree.allRecords()
        let currentJailed = jailedProcessesLock.withLock { $0 }

        var newlyJailed: [(key: ProcessKey, ruleID: UUID, pid: pid_t)] = []
        for record in allRecords {
            let key = ProcessKey(pid: record.identity.pid, pidVersion: record.identity.pidVersion)
            guard currentJailed[key] == nil else { continue }
            guard let rule = rules.first(where: {
                $0.jailedSignature.matches(resolvedTeamID: record.teamID, signingID: record.signingID)
            }) else { continue }
            newlyJailed.append((key: key, ruleID: rule.id, pid: record.identity.pid))
        }

        guard !newlyJailed.isEmpty else { return }

        jailedProcessesLock.withLock {
            for entry in newlyJailed { $0[entry.key] = entry.ruleID }
        }
        if let client { es_clear_cache(client) }
        logger.info("ESJailAdapter sweep: added \(newlyJailed.count, privacy: .public) untracked processes to jail")

        let seeds = newlyJailed.map { (pid: $0.pid, ruleID: $0.ruleID) }
        jailCascadeQueue.async { [self] in
            cascadeJailToDescendants(seeds: seeds, allRecords: allRecords)
        }
    }

    private func cascadeJailToDescendants(seeds: [(pid: pid_t, ruleID: UUID)], allRecords: [ProcessRecord]) {
        var frontier = seeds
        var visited = Set(seeds.map { $0.pid })

        while !frontier.isEmpty {
            let parentMap = Dictionary(uniqueKeysWithValues: frontier.map { ($0.pid, $0.ruleID) })
            var nextFrontier: [(pid: pid_t, ruleID: UUID)] = []
            var batch: [(ProcessKey, UUID)] = []

            for record in allRecords {
                guard let ruleID = parentMap[record.parentIdentity.pid] else { continue }
                let childPID = record.identity.pid
                guard !visited.contains(childPID) else { continue }
                let key = ProcessKey(pid: childPID, pidVersion: record.identity.pidVersion)
                guard !jailedProcessesLock.withLock({ $0[key] != nil }) else { continue }
                visited.insert(childPID)
                batch.append((key, ruleID))
                nextFrontier.append((pid: childPID, ruleID: ruleID))
            }

            if !batch.isEmpty {
                jailedProcessesLock.withLock {
                    for (key, ruleID) in batch { $0[key] = ruleID }
                }
                if let client { es_clear_cache(client) }
                logger.info("ESJailAdapter cascade: jailed \(batch.count, privacy: .public) descendant processes")
            }

            frontier = nextFrontier
        }
    }
}
