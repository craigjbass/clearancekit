//
//  XPCServer.swift
//  opfilter
//
//  Thin coordinator: sets up the XPC listener, wires PolicyRepository,
//  EventBroadcaster, FAAFilterInteractor, JailFilterInteractor, and ESInboundAdapter together.
//
//  The listener starts immediately on init/start() with just the broadcaster, so the GUI
//  can connect during opfilter startup. Once all dependencies are ready, configure(_:)
//  sets the ServerContext and pushes initial state to any clients that connected early.
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "xpc-server")

private let jailEnabledFile = URL(fileURLWithPath: "/Library/Application Support/clearancekit/jail-enabled")

final class XPCServer: NSObject, @unchecked Sendable {

    // MARK: - ServerContext

    /// All dependencies that become available after the initial process-tree scan
    /// and policy loading. Passed in via configure(_:) once startup completes.
    struct ServerContext {
        let processTree: ProcessTreeProtocol
        let policyRepository: PolicyRepository
        let faaInteractor: FAAFilterInteractor
        let jailInteractor: JailFilterInteractor
        let adapter: ESInboundAdapter
        let jailAdapter: ESJailAdapter
    }

    // MARK: - Stored state

    private var listener: NSXPCListener?
    private let broadcaster: EventBroadcaster
    fileprivate let serverQueue: DispatchQueue
    /// Protected by contextLock so it can be read from main.swift after configure()
    /// without waiting for the serverQueue dispatch to complete.
    private let contextLock = OSAllocatedUnfairLock<ServerContext?>(initialState: nil)
    private var context: ServerContext? { contextLock.withLock { $0 } }

    // MARK: - Init

    init(
        broadcaster: EventBroadcaster,
        serverQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.xpc-server", qos: .userInitiated)
    ) {
        self.broadcaster = broadcaster
        self.serverQueue = serverQueue
        super.init()
    }

    // MARK: - Lifecycle

    func start() {
        listener = NSXPCListener(machServiceName: XPCConstants.serviceName)
        listener?.delegate = self
        listener?.resume()
    }

    /// Called once all dependencies are initialised. Sets the server context and
    /// pushes the initial policy snapshot to any GUI clients that connected early.
    func configure(_ context: ServerContext) {
        contextLock.withLock { $0 = context }
        serverQueue.async { [self] in
            broadcaster.broadcastToAllClients { [self] proxy in
                pushPolicySnapshot(to: proxy, context: context)
            }
        }
    }

    // MARK: - Event broadcasting

    func handleXProtectChange() {
        serverQueue.async { [self] in
            guard let context else { return }
            let reloaded = enumerateXProtectEntries()
            guard context.policyRepository.updateXProtectEntries(reloaded) else { return }
            applyAllowlistToFilter()
        }
    }

    func handleEvent(_ event: FolderOpenEvent) {
        serverQueue.async { [self] in
            broadcaster.broadcast(event)
        }
    }

    func handleTamperEvent(_ event: TamperAttemptEvent) {
        serverQueue.async { [self] in
            broadcaster.broadcast(event)
        }
    }

    func pushMetrics(_ metrics: PipelineMetrics, jail: JailMetrics, timestamp: Date) {
        let snapshot = PipelineMetricsSnapshot(
            eventBufferEnqueueCount: metrics.eventBufferEnqueueCount,
            eventBufferDropCount:    metrics.eventBufferDropCount,
            hotPathProcessedCount:   metrics.hotPathProcessedCount,
            hotPathRespondedCount:   metrics.hotPathRespondedCount,
            slowQueueEnqueueCount:   metrics.slowQueueEnqueueCount,
            slowQueueDropCount:      metrics.slowQueueDropCount,
            slowPathProcessedCount:  metrics.slowPathProcessedCount,
            jailEvaluatedCount:      jail.jailEvaluatedCount,
            jailDenyCount:           jail.jailDenyCount,
            timestamp:               timestamp
        )
        serverQueue.async { [self] in
            broadcaster.broadcastToAllClients { $0.metricsUpdated(snapshot) }
        }
    }

    // MARK: - Policy / allowlist assembly

    func mergedRules() -> [FAARule] {
        context?.policyRepository.mergedRules() ?? []
    }

    func mergedJailRules() -> [JailRule] {
        context?.policyRepository.mergedJailRules() ?? []
    }

    // MARK: - Jail adapter lifecycle

    var isJailEnabled: Bool {
        FileManager.default.fileExists(atPath: jailEnabledFile.path)
    }

    func startJailAdapterIfEnabled() {
        guard let context, isJailEnabled else { return }
        let rules = context.policyRepository.mergedJailRules()
        context.jailAdapter.start(initialRules: rules)
    }

    fileprivate func setJailEnabled(_ enabled: Bool) {
        guard let context else { return }
        if enabled {
            if !FileManager.default.createFile(atPath: jailEnabledFile.path, contents: nil) {
                logger.error("XPCServer: Failed to create jail-enabled flag file")
            }
            let rules = context.policyRepository.mergedJailRules()
            context.jailAdapter.start(initialRules: rules)
        } else {
            try? FileManager.default.removeItem(at: jailEnabledFile)
            context.jailAdapter.stop()
        }
        broadcaster.broadcastToAllClients { $0.jailEnabledUpdated(enabled) }
    }

    fileprivate func setMCPEnabled(_ enabled: Bool) {
        guard let context else { return }
        context.policyRepository.setMCPEnabled(enabled)
        broadcaster.broadcastToAllClients { $0.mcpEnabledUpdated(enabled) }
    }

    // MARK: - Filter application

    func applyPolicyToFilter() {
        guard let context else { return }
        context.adapter.updatePolicy(context.policyRepository.mergedRules())
    }

    func applyAllowlistToFilter() {
        guard let context else { return }
        context.faaInteractor.updateAllowlist(context.policyRepository.mergedAllowlist())
        context.faaInteractor.updateAncestorAllowlist(context.policyRepository.mergedAncestorAllowlist())
    }

    func applyJailRulesToFilter() {
        guard let context else { return }
        let rules = context.policyRepository.mergedJailRules()
        context.jailInteractor.updateJailRules(rules)
        context.jailAdapter.updateJailRules(rules)
    }

    // MARK: - Client registration

    fileprivate func addGUIClient(_ connection: NSXPCConnection) {
        _ = broadcaster.addClient(connection)
        guard let context else {
            (connection.remoteObjectProxy as? ClientProtocol)?.serviceReady(false)
            return
        }
        guard let proxy = connection.remoteObjectProxy as? ClientProtocol else { return }
        if let notification = context.policyRepository.pendingSignatureIssueNotification() {
            proxy.signatureIssueDetected(notification)
        }
        pushPolicySnapshot(to: proxy, context: context)
    }

    fileprivate func removeClient(_ connection: NSXPCConnection) {
        _ = broadcaster.removeClient(connection)
    }

    fileprivate func beginAllowStream(for connection: NSXPCConnection) -> [FolderOpenEvent] {
        broadcaster.beginAllowStream(for: connection)
    }

    fileprivate func endAllowStream(for connection: NSXPCConnection) {
        broadcaster.endAllowStream(for: connection)
    }

    fileprivate func recentEvents() -> [FolderOpenEvent] {
        broadcaster.recentEvents()
    }

    fileprivate func recentTamperEvents() -> [TamperAttemptEvent] {
        broadcaster.recentTamperEvents()
    }

    // MARK: - Rule mutations

    fileprivate func applyAddRule(_ rule: FAARule) {
        guard let context else { return }
        context.policyRepository.addRule(rule)
        applyPolicyToFilter()
        broadcaster.broadcastToAllClients { $0.userRulesUpdated(context.policyRepository.encodedUserRules()) }
    }

    fileprivate func applyUpdateRule(_ rule: FAARule) {
        guard let context else { return }
        context.policyRepository.updateRule(rule)
        applyPolicyToFilter()
        broadcaster.broadcastToAllClients { $0.userRulesUpdated(context.policyRepository.encodedUserRules()) }
    }

    fileprivate func applyRemoveRule(ruleID: UUID) {
        guard let context else { return }
        context.policyRepository.removeRule(ruleID: ruleID)
        applyPolicyToFilter()
        broadcaster.broadcastToAllClients { $0.userRulesUpdated(context.policyRepository.encodedUserRules()) }
    }

    // MARK: - Allowlist mutations

    fileprivate func applyAddAllowlistEntry(_ entry: AllowlistEntry) {
        guard let context else { return }
        context.policyRepository.addAllowlistEntry(entry)
        applyAllowlistToFilter()
        broadcaster.broadcastToAllClients { $0.userAllowlistUpdated(context.policyRepository.encodedUserAllowlist()) }
    }

    fileprivate func applyRemoveAllowlistEntry(entryID: UUID) {
        guard let context else { return }
        context.policyRepository.removeAllowlistEntry(entryID: entryID)
        applyAllowlistToFilter()
        broadcaster.broadcastToAllClients { $0.userAllowlistUpdated(context.policyRepository.encodedUserAllowlist()) }
    }

    // MARK: - Ancestor allowlist mutations

    fileprivate func applyAddAncestorAllowlistEntry(_ entry: AncestorAllowlistEntry) {
        guard let context else { return }
        context.policyRepository.addAncestorAllowlistEntry(entry)
        applyAllowlistToFilter()
        broadcaster.broadcastToAllClients { $0.userAncestorAllowlistUpdated(context.policyRepository.encodedUserAncestorAllowlist()) }
    }

    fileprivate func applyRemoveAncestorAllowlistEntry(entryID: UUID) {
        guard let context else { return }
        context.policyRepository.removeAncestorAllowlistEntry(entryID: entryID)
        applyAllowlistToFilter()
        broadcaster.broadcastToAllClients { $0.userAncestorAllowlistUpdated(context.policyRepository.encodedUserAncestorAllowlist()) }
    }

    // MARK: - Jail rule mutations

    fileprivate func applyAddJailRule(_ rule: JailRule) {
        guard let context else { return }
        context.policyRepository.addJailRule(rule)
        applyJailRulesToFilter()
        context.adapter.clearCache()
        broadcaster.broadcastToAllClients { $0.userJailRulesUpdated(context.policyRepository.encodedUserJailRules()) }
    }

    fileprivate func applyUpdateJailRule(_ rule: JailRule) {
        guard let context else { return }
        context.policyRepository.updateJailRule(rule)
        applyJailRulesToFilter()
        context.adapter.clearCache()
        broadcaster.broadcastToAllClients { $0.userJailRulesUpdated(context.policyRepository.encodedUserJailRules()) }
    }

    fileprivate func applyRemoveJailRule(ruleID: UUID) {
        guard let context else { return }
        context.policyRepository.removeJailRule(ruleID: ruleID)
        applyJailRulesToFilter()
        context.adapter.clearCache()
        broadcaster.broadcastToAllClients { $0.userJailRulesUpdated(context.policyRepository.encodedUserJailRules()) }
    }

    // MARK: - Bundle updater signature mutations

    fileprivate func applySaveBundleUpdaterSignatures(_ signatures: [BundleUpdaterSignature]) {
        guard let context else { return }
        context.policyRepository.setBundleUpdaterSignatures(signatures)
        broadcaster.broadcastToAllClients { $0.bundleUpdaterSignaturesUpdated(context.policyRepository.encodedBundleUpdaterSignatures()) }
    }

    // MARK: - Jailed process query

    fileprivate func activeJailedProcesses() -> [RunningProcessInfo] {
        guard let context else { return [] }
        return ProcessEnumerator.enumerate(pids: context.jailAdapter.activeJailedPIDs())
    }

    // MARK: - Process tree snapshot

    fileprivate func processTreeSnapshot() -> [RunningProcessInfo] {
        guard let context else { return [] }
        return context.processTree.allRecords().map { record in
            RunningProcessInfo(
                pid: record.identity.pid,
                pidVersion: record.identity.pidVersion,
                parentPID: record.parentIdentity.pid,
                parentPIDVersion: record.parentIdentity.pidVersion,
                path: record.path,
                teamID: record.teamID,
                signingID: record.signingID,
                uid: record.uid,
                gid: record.gid
            )
        }
    }

    // MARK: - Discovery mode

    fileprivate func beginDiscovery() {
        guard let context else { return }
        context.adapter.setDiscoveryPaths(["/Users"])
    }

    fileprivate func endDiscovery() {
        guard let context else { return }
        context.adapter.setDiscoveryPaths([])
    }

    // MARK: - Signature issue resolution

    fileprivate func resolveSignatureIssue(approved: Bool) {
        guard let context else { return }
        context.policyRepository.resolveSignatureIssue(approved: approved)
        applyPolicyToFilter()
        applyAllowlistToFilter()
        broadcaster.broadcastToAllClients { $0.userRulesUpdated(context.policyRepository.encodedUserRules()) }
        broadcaster.broadcastToAllClients { $0.userAllowlistUpdated(context.policyRepository.encodedUserAllowlist()) }
    }

    // MARK: - Resync

    fileprivate func requestResync(requestingConnection: NSXPCConnection, reply: @escaping () -> Void) {
        serverQueue.async { [self] in
            guard let context else { reply(); return }
            let reloadedRules = ManagedPolicyLoader.loadWithSync()
            let reloadedAllowlist = ManagedAllowlistLoader.loadWithSync()
            let reloadedJailRules = ManagedJailRuleLoader.loadWithSync()
            let reloadedXProtect = enumerateXProtectEntries()

            context.policyRepository.resync(
                managedRules: reloadedRules,
                managedAllowlist: reloadedAllowlist,
                managedJailRules: reloadedJailRules,
                xprotectEntries: reloadedXProtect
            )

            applyPolicyToFilter()
            applyAllowlistToFilter()
            applyJailRulesToFilter()
            guard let proxy = requestingConnection.remoteObjectProxy as? ClientProtocol else { reply(); return }
            pushPolicySnapshot(to: proxy, context: context)
            reply()
        }
    }

    // MARK: - Snapshot push

    private func pushPolicySnapshot(to proxy: ClientProtocol, context: ServerContext) {
        proxy.managedRulesUpdated(context.policyRepository.encodedManagedRules())
        proxy.userRulesUpdated(context.policyRepository.encodedUserRules())
        proxy.managedAllowlistUpdated(context.policyRepository.encodedManagedAllowlist())
        proxy.userAllowlistUpdated(context.policyRepository.encodedUserAllowlist())
        proxy.managedAncestorAllowlistUpdated(context.policyRepository.encodedManagedAncestorAllowlist())
        proxy.userAncestorAllowlistUpdated(context.policyRepository.encodedUserAncestorAllowlist())
        proxy.managedJailRulesUpdated(context.policyRepository.encodedManagedJailRules())
        proxy.userJailRulesUpdated(context.policyRepository.encodedUserJailRules())
        proxy.jailEnabledUpdated(isJailEnabled)
        proxy.mcpEnabledUpdated(context.policyRepository.mcpEnabled)
        proxy.bundleUpdaterSignaturesUpdated(context.policyRepository.encodedBundleUpdaterSignatures())
        proxy.serviceReady(true)
    }
}

// MARK: - NSXPCListenerDelegate

extension XPCServer: NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        let exportedInterface = NSXPCInterface(with: ServiceProtocol.self)
        let eventClasses = NSSet(array: [FolderOpenEvent.self, AncestorInfo.self, NSArray.self, NSDate.self, NSString.self, NSUUID.self]) as! Set<AnyHashable>
        exportedInterface.setClasses(
            eventClasses,
            for: #selector(ServiceProtocol.fetchRecentEvents(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        let processInfoClasses = NSSet(array: [NSArray.self, RunningProcessInfo.self]) as! Set<AnyHashable>
        exportedInterface.setClasses(
            processInfoClasses,
            for: #selector(ServiceProtocol.fetchProcessList(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        exportedInterface.setClasses(
            processInfoClasses,
            for: #selector(ServiceProtocol.fetchActiveJailedProcesses(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        exportedInterface.setClasses(
            processInfoClasses,
            for: #selector(ServiceProtocol.fetchProcessTree(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        let tamperClasses = NSSet(array: [TamperAttemptEvent.self, NSArray.self, NSDate.self, NSUUID.self, NSString.self]) as! Set<AnyHashable>
        exportedInterface.setClasses(
            tamperClasses,
            for: #selector(ServiceProtocol.fetchRecentTamperEvents(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        newConnection.exportedInterface = exportedInterface
        newConnection.exportedObject = ConnectionHandler(server: self, connection: newConnection)

        let remoteInterface = NSXPCInterface(with: ClientProtocol.self)
        remoteInterface.setClasses(
            eventClasses,
            for: #selector(ClientProtocol.folderOpened(_:)),
            argumentIndex: 0,
            ofReply: false
        )
        remoteInterface.setClasses(
            NSSet(array: [SignatureIssueNotification.self]) as! Set<AnyHashable>,
            for: #selector(ClientProtocol.signatureIssueDetected(_:)),
            argumentIndex: 0,
            ofReply: false
        )
        remoteInterface.setClasses(
            NSSet(array: [PipelineMetricsSnapshot.self]) as! Set<AnyHashable>,
            for: #selector(ClientProtocol.metricsUpdated(_:)),
            argumentIndex: 0,
            ofReply: false
        )
        remoteInterface.setClasses(
            NSSet(array: [TamperAttemptEvent.self]) as! Set<AnyHashable>,
            for: #selector(ClientProtocol.tamperAttemptDenied(_:)),
            argumentIndex: 0,
            ofReply: false
        )
        newConnection.remoteObjectInterface = remoteInterface

        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            guard let conn = newConnection, let self else { return }
            serverQueue.async { self.removeClient(conn) }
        }
        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            guard let conn = newConnection, let self else { return }
            serverQueue.async {
                logger.error("XPCServer: Connection interrupted")
                self.removeClient(conn)
            }
        }

        guard ConnectionValidator.validate(newConnection) else {
            logger.error("XPCServer: Rejected connection — validation failed")
            return false
        }

        newConnection.resume()
        return true
    }
}

// MARK: - ConnectionHandler

private final class ConnectionHandler: NSObject, ServiceProtocol {
    weak var server: XPCServer?
    weak var connection: NSXPCConnection?

    init(server: XPCServer, connection: NSXPCConnection) {
        self.server = server
        self.connection = connection
        super.init()
    }

    func registerClient(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server else { reply(false); return }
        server.serverQueue.async {
            server.addGUIClient(conn)
            reply(true)
        }
    }

    func unregisterClient(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server else { reply(false); return }
        server.serverQueue.async {
            server.removeClient(conn)
            reply(true)
        }
    }

    func fetchRecentEvents(withReply reply: @escaping ([FolderOpenEvent]) -> Void) {
        guard let server else { reply([]); return }
        server.serverQueue.async {
            reply(server.recentEvents())
        }
    }

    func fetchRecentTamperEvents(withReply reply: @escaping ([TamperAttemptEvent]) -> Void) {
        guard let server else { reply([]); return }
        server.serverQueue.async {
            reply(server.recentTamperEvents())
        }
    }

    func fetchVersionInfo(withReply reply: @escaping (NSString) -> Void) {
        reply(BuildInfo.gitHash as NSString)
    }

    func addRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let rule = try? JSONDecoder().decode(FAARule.self, from: ruleData as Data) else {
            reply(false)
            return
        }
        server.serverQueue.async {
            server.applyAddRule(rule)
            reply(true)
        }
    }

    func updateRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let rule = try? JSONDecoder().decode(FAARule.self, from: ruleData as Data) else {
            reply(false)
            return
        }
        server.serverQueue.async {
            server.applyUpdateRule(rule)
            reply(true)
        }
    }

    func removeRule(_ ruleID: NSUUID, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        server.serverQueue.async {
            server.applyRemoveRule(ruleID: ruleID as UUID)
            reply(true)
        }
    }

    func addAllowlistEntry(_ entryData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let entry = try? JSONDecoder().decode(AllowlistEntry.self, from: entryData as Data) else {
            reply(false)
            return
        }
        server.serverQueue.async {
            server.applyAddAllowlistEntry(entry)
            reply(true)
        }
    }

    func removeAllowlistEntry(_ entryID: NSUUID, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        server.serverQueue.async {
            server.applyRemoveAllowlistEntry(entryID: entryID as UUID)
            reply(true)
        }
    }

    func addAncestorAllowlistEntry(_ entryData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let entry = try? JSONDecoder().decode(AncestorAllowlistEntry.self, from: entryData as Data) else {
            reply(false)
            return
        }
        server.serverQueue.async {
            server.applyAddAncestorAllowlistEntry(entry)
            reply(true)
        }
    }

    func removeAncestorAllowlistEntry(_ entryID: NSUUID, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        server.serverQueue.async {
            server.applyRemoveAncestorAllowlistEntry(entryID: entryID as UUID)
            reply(true)
        }
    }

    func addJailRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let rule = try? JSONDecoder().decode(JailRule.self, from: ruleData as Data) else {
            reply(false)
            return
        }
        server.serverQueue.async {
            server.applyAddJailRule(rule)
            reply(true)
        }
    }

    func updateJailRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let rule = try? JSONDecoder().decode(JailRule.self, from: ruleData as Data) else {
            reply(false)
            return
        }
        server.serverQueue.async {
            server.applyUpdateJailRule(rule)
            reply(true)
        }
    }

    func removeJailRule(_ ruleID: NSUUID, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        server.serverQueue.async {
            server.applyRemoveJailRule(ruleID: ruleID as UUID)
            reply(true)
        }
    }

    func requestResync(withReply reply: @escaping () -> Void) {
        guard let server, let conn = connection else { reply(); return }
        server.requestResync(requestingConnection: conn, reply: reply)
    }

    func beginDiscovery(withReply reply: @escaping () -> Void) {
        guard let server else { reply(); return }
        server.serverQueue.async {
            server.beginDiscovery()
            reply()
        }
    }

    func endDiscovery(withReply reply: @escaping () -> Void) {
        guard let server else { reply(); return }
        server.serverQueue.async {
            server.endDiscovery()
            reply()
        }
    }

    func beginAllowEventStream(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server else { reply(false); return }
        server.serverQueue.async {
            let backfill = server.beginAllowStream(for: conn)
            guard let proxy = conn.remoteObjectProxy as? ClientProtocol else {
                reply(true)
                return
            }
            let batchSize = 50
            for batchStart in stride(from: 0, to: backfill.count, by: batchSize) {
                let batchEnd = min(batchStart + batchSize, backfill.count)
                for event in backfill[batchStart..<batchEnd] {
                    proxy.folderOpened(event)
                }
            }
            reply(true)
        }
    }

    func endAllowEventStream(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server else { reply(false); return }
        server.serverQueue.async {
            server.endAllowStream(for: conn)
            reply(true)
        }
    }

    func fetchProcessList(withReply reply: @escaping ([RunningProcessInfo]) -> Void) {
        guard let server else { reply([]); return }
        server.serverQueue.async {
            reply(ProcessEnumerator.enumerateAll())
        }
    }

    func fetchActiveJailedProcesses(withReply reply: @escaping ([RunningProcessInfo]) -> Void) {
        guard let server else { reply([]); return }
        server.serverQueue.async {
            reply(server.activeJailedProcesses())
        }
    }

    func fetchProcessTree(withReply reply: @escaping ([RunningProcessInfo]) -> Void) {
        guard let server else { reply([]); return }
        server.serverQueue.async {
            reply(server.processTreeSnapshot())
        }
    }

    func resolveSignatureIssue(approved: Bool, withReply reply: @escaping () -> Void) {
        guard let server else { reply(); return }
        server.serverQueue.async {
            server.resolveSignatureIssue(approved: approved)
            reply()
        }
    }

    func setJailEnabled(_ enabled: Bool, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        server.serverQueue.async {
            server.setJailEnabled(enabled)
            reply(true)
        }
    }

    func setMCPEnabled(_ enabled: Bool, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        server.serverQueue.async {
            server.setMCPEnabled(enabled)
            reply(true)
        }
    }

    func saveBundleUpdaterSignatures(_ signaturesData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        guard let signatures = try? JSONDecoder().decode([BundleUpdaterSignature].self, from: signaturesData as Data) else {
            reply(false); return
        }
        server.serverQueue.async {
            server.applySaveBundleUpdaterSignatures(signatures)
            reply(true)
        }
    }
}
