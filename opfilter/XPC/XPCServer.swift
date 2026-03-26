//
//  XPCServer.swift
//  opfilter
//
//  Thin coordinator: sets up the XPC listener, wires PolicyRepository,
//  EventBroadcaster, FilterInteractor, and ESInboundAdapter together.
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "xpc-server")

private let jailEnabledFile = URL(fileURLWithPath: "/Library/Application Support/clearancekit/jail-enabled")

final class XPCServer: NSObject, @unchecked Sendable {
    private var listener: NSXPCListener?
    private let policyRepository: PolicyRepository
    private let broadcaster: EventBroadcaster
    private let interactor: FilterInteractor
    private let adapter: ESInboundAdapter
    private let jailAdapter: ESJailAdapter
    fileprivate let serverQueue: DispatchQueue

    init(
        policyRepository: PolicyRepository,
        broadcaster: EventBroadcaster,
        interactor: FilterInteractor,
        adapter: ESInboundAdapter,
        jailAdapter: ESJailAdapter,
        serverQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.xpc-server", qos: .userInitiated)
    ) {
        self.policyRepository = policyRepository
        self.broadcaster = broadcaster
        self.interactor = interactor
        self.adapter = adapter
        self.jailAdapter = jailAdapter
        self.serverQueue = serverQueue
        super.init()
    }

    func start() {
        listener = NSXPCListener(machServiceName: XPCConstants.serviceName)
        listener?.delegate = self
        listener?.resume()
    }

    func handleXProtectChange() {
        serverQueue.async { [self] in
            let reloaded = enumerateXProtectEntries()
            guard policyRepository.updateXProtectEntries(reloaded) else { return }
            applyAllowlistToFilter()
        }
    }

    // MARK: - Direct filter integration

    func handleEvent(_ event: FolderOpenEvent) {
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
        policyRepository.mergedRules()
    }

    func mergedJailRules() -> [JailRule] {
        policyRepository.mergedJailRules()
    }

    // MARK: - Jail adapter lifecycle

    var isJailEnabled: Bool {
        FileManager.default.fileExists(atPath: jailEnabledFile.path)
    }

    func startJailAdapterIfEnabled() {
        guard isJailEnabled else { return }
        let rules = policyRepository.mergedJailRules()
        jailAdapter.start(initialRules: rules)
    }

    fileprivate func setJailEnabled(_ enabled: Bool) {
        if enabled {
            if !FileManager.default.createFile(atPath: jailEnabledFile.path, contents: nil) {
                logger.error("XPCServer: Failed to create jail-enabled flag file")
            }
            let rules = policyRepository.mergedJailRules()
            jailAdapter.start(initialRules: rules)
        } else {
            try? FileManager.default.removeItem(at: jailEnabledFile)
            jailAdapter.stop()
        }
        broadcaster.broadcastToAllClients { $0.jailEnabledUpdated(enabled) }
    }

    // MARK: - Filter application

    func applyPolicyToFilter() {
        adapter.updatePolicy(policyRepository.mergedRules())
    }

    func applyAllowlistToFilter() {
        interactor.updateAllowlist(policyRepository.mergedAllowlist())
        interactor.updateAncestorAllowlist(policyRepository.mergedAncestorAllowlist())
    }

    func applyJailRulesToFilter() {
        let rules = policyRepository.mergedJailRules()
        interactor.updateJailRules(rules)
        jailAdapter.updateJailRules(rules)
    }

    // MARK: - Client registration

    fileprivate func addGUIClient(_ connection: NSXPCConnection) {
        _ = broadcaster.addClient(connection)
        if let notification = policyRepository.pendingSignatureIssueNotification() {
            (connection.remoteObjectProxy as? ClientProtocol)?.signatureIssueDetected(notification)
        }
    }

    fileprivate func removeClient(_ connection: NSXPCConnection) {
        _ = broadcaster.removeClient(connection)
    }

    fileprivate func recentEvents() -> [FolderOpenEvent] {
        broadcaster.recentEvents()
    }

    // MARK: - Rule mutations

    fileprivate func applyAddRule(_ rule: FAARule) {
        policyRepository.addRule(rule)
        applyPolicyToFilter()
        broadcaster.broadcastToAllClients { $0.userRulesUpdated(self.policyRepository.encodedUserRules()) }
    }

    fileprivate func applyUpdateRule(_ rule: FAARule) {
        policyRepository.updateRule(rule)
        applyPolicyToFilter()
        broadcaster.broadcastToAllClients { $0.userRulesUpdated(self.policyRepository.encodedUserRules()) }
    }

    fileprivate func applyRemoveRule(ruleID: UUID) {
        policyRepository.removeRule(ruleID: ruleID)
        applyPolicyToFilter()
        broadcaster.broadcastToAllClients { $0.userRulesUpdated(self.policyRepository.encodedUserRules()) }
    }

    // MARK: - Allowlist mutations

    fileprivate func applyAddAllowlistEntry(_ entry: AllowlistEntry) {
        policyRepository.addAllowlistEntry(entry)
        applyAllowlistToFilter()
        broadcaster.broadcastToAllClients { $0.userAllowlistUpdated(self.policyRepository.encodedUserAllowlist()) }
    }

    fileprivate func applyRemoveAllowlistEntry(entryID: UUID) {
        policyRepository.removeAllowlistEntry(entryID: entryID)
        applyAllowlistToFilter()
        broadcaster.broadcastToAllClients { $0.userAllowlistUpdated(self.policyRepository.encodedUserAllowlist()) }
    }

    // MARK: - Ancestor allowlist mutations

    fileprivate func applyAddAncestorAllowlistEntry(_ entry: AncestorAllowlistEntry) {
        policyRepository.addAncestorAllowlistEntry(entry)
        applyAllowlistToFilter()
        broadcaster.broadcastToAllClients { $0.userAncestorAllowlistUpdated(self.policyRepository.encodedUserAncestorAllowlist()) }
    }

    fileprivate func applyRemoveAncestorAllowlistEntry(entryID: UUID) {
        policyRepository.removeAncestorAllowlistEntry(entryID: entryID)
        applyAllowlistToFilter()
        broadcaster.broadcastToAllClients { $0.userAncestorAllowlistUpdated(self.policyRepository.encodedUserAncestorAllowlist()) }
    }

    // MARK: - Jail rule mutations

    fileprivate func applyAddJailRule(_ rule: JailRule) {
        policyRepository.addJailRule(rule)
        applyJailRulesToFilter()
        adapter.clearCache()
        broadcaster.broadcastToAllClients { $0.userJailRulesUpdated(self.policyRepository.encodedUserJailRules()) }
    }

    fileprivate func applyUpdateJailRule(_ rule: JailRule) {
        policyRepository.updateJailRule(rule)
        applyJailRulesToFilter()
        adapter.clearCache()
        broadcaster.broadcastToAllClients { $0.userJailRulesUpdated(self.policyRepository.encodedUserJailRules()) }
    }

    fileprivate func applyRemoveJailRule(ruleID: UUID) {
        policyRepository.removeJailRule(ruleID: ruleID)
        applyJailRulesToFilter()
        adapter.clearCache()
        broadcaster.broadcastToAllClients { $0.userJailRulesUpdated(self.policyRepository.encodedUserJailRules()) }
    }

    // MARK: - Jailed process query

    fileprivate func activeJailedProcesses() -> [RunningProcessInfo] {
        ProcessEnumerator.enumerate(pids: jailAdapter.activeJailedPIDs())
    }

    // MARK: - Discovery mode

    fileprivate func beginDiscovery() {
        adapter.setDiscoveryPaths(["/Users"])
    }

    fileprivate func endDiscovery() {
        adapter.setDiscoveryPaths([])
    }

    // MARK: - Signature issue resolution

    fileprivate func resolveSignatureIssue(approved: Bool) {
        policyRepository.resolveSignatureIssue(approved: approved)
        applyPolicyToFilter()
        applyAllowlistToFilter()
        broadcaster.broadcastToAllClients { $0.userRulesUpdated(self.policyRepository.encodedUserRules()) }
        broadcaster.broadcastToAllClients { $0.userAllowlistUpdated(self.policyRepository.encodedUserAllowlist()) }
    }

    // MARK: - Resync

    fileprivate func requestResync(requestingConnection: NSXPCConnection, reply: @escaping () -> Void) {
        serverQueue.async { [self] in
            let reloadedRules = ManagedPolicyLoader.loadWithSync()
            let reloadedAllowlist = ManagedAllowlistLoader.loadWithSync()
            let reloadedJailRules = ManagedJailRuleLoader.loadWithSync()
            let reloadedXProtect = enumerateXProtectEntries()

            policyRepository.resync(
                managedRules: reloadedRules,
                managedAllowlist: reloadedAllowlist,
                managedJailRules: reloadedJailRules,
                xprotectEntries: reloadedXProtect
            )

            applyPolicyToFilter()
            applyAllowlistToFilter()
            applyJailRulesToFilter()
            pushPolicySnapshotToGUIClient(requestingConnection)
            reply()
        }
    }

    // MARK: - Snapshot push

    fileprivate func pushPolicySnapshotToGUIClient(_ connection: NSXPCConnection) {
        let proxy = connection.remoteObjectProxy as? ClientProtocol
        proxy?.managedRulesUpdated(policyRepository.encodedManagedRules())
        proxy?.userRulesUpdated(policyRepository.encodedUserRules())
        proxy?.managedAllowlistUpdated(policyRepository.encodedManagedAllowlist())
        proxy?.userAllowlistUpdated(policyRepository.encodedUserAllowlist())
        proxy?.managedAncestorAllowlistUpdated(policyRepository.encodedManagedAncestorAllowlist())
        proxy?.userAncestorAllowlistUpdated(policyRepository.encodedUserAncestorAllowlist())
        proxy?.managedJailRulesUpdated(policyRepository.encodedManagedJailRules())
        proxy?.userJailRulesUpdated(policyRepository.encodedUserJailRules())
        proxy?.jailEnabledUpdated(isJailEnabled)
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
}

