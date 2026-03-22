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

private let dataDirectory = URL(fileURLWithPath: "/Library/Application Support/clearancekit")

final class XPCServer: NSObject, @unchecked Sendable {
    private var listener: NSXPCListener?
    private let policyRepository: PolicyRepository
    private let broadcaster: EventBroadcaster
    private let interactor: FilterInteractor
    private let adapter: ESInboundAdapter
    private let jailAdapter: ESJailAdapter

    init(interactor: FilterInteractor, adapter: ESInboundAdapter, jailAdapter: ESJailAdapter) {
        let database = Database(directory: dataDirectory)
        let managedRules = ManagedPolicyLoader.load()
        let managedAllowlist = ManagedAllowlistLoader.load()
        let managedJailRules = ManagedJailRuleLoader.load()
        let xprotectEntries = enumerateXProtectEntries()
        let xprotectCount = xprotectEntries.count

        self.policyRepository = PolicyRepository(
            database: database,
            managedRules: managedRules,
            managedAllowlist: managedAllowlist,
            managedJailRules: managedJailRules,
            xprotectEntries: xprotectEntries
        )
        self.broadcaster = EventBroadcaster()
        self.interactor = interactor
        self.adapter = adapter
        self.jailAdapter = jailAdapter

        super.init()

        logger.info("XPCServer: Discovered \(xprotectCount) XProtect allowlist entry/entries")
        applyPolicyToFilter()
        applyAllowlistToFilter()
        applyJailRulesToFilter()
    }

    func start() {
        listener = NSXPCListener(machServiceName: XPCConstants.serviceName)
        listener?.delegate = self
        listener?.resume()
        logger.info("XPCServer: Listening on \(XPCConstants.serviceName, privacy: .public)")
    }

    func handleXProtectChange() {
        Task {
            let reloaded = enumerateXProtectEntries()
            guard policyRepository.updateXProtectEntries(reloaded) else { return }
            applyAllowlistToFilter()
            logger.info("XPCServer: XProtect bundle changed — reloaded \(reloaded.count) entry/entries")
        }
    }

    // MARK: - Direct filter integration

    func handleEvent(_ event: FolderOpenEvent) {
        broadcaster.broadcast(event)
    }

    // MARK: - Policy / allowlist assembly

    func mergedRules() -> [FAARule] {
        policyRepository.mergedRules()
    }

    func mergedJailRules() -> [JailRule] {
        policyRepository.mergedJailRules()
    }

    // MARK: - Filter application

    private func applyPolicyToFilter() {
        adapter.updatePolicy(policyRepository.mergedRules())
    }

    private func applyAllowlistToFilter() {
        interactor.updateAllowlist(policyRepository.mergedAllowlist())
        interactor.updateAncestorAllowlist(policyRepository.mergedAncestorAllowlist())
    }

    private func applyJailRulesToFilter() {
        let rules = policyRepository.mergedJailRules()
        interactor.updateJailRules(rules)
        jailAdapter.updateJailRules(rules)
    }

    // MARK: - Client registration

    fileprivate func addGUIClient(_ connection: NSXPCConnection) {
        let count = broadcaster.addClient(connection)
        logger.debug("XPCServer: GUI client registered. Active clients: \(count)")
        if let notification = policyRepository.pendingSignatureIssueNotification() {
            (connection.remoteObjectProxy as? ClientProtocol)?.signatureIssueDetected(notification)
        }
    }

    fileprivate func removeClient(_ connection: NSXPCConnection) {
        let count = broadcaster.removeClient(connection)
        logger.debug("XPCServer: Client removed. GUI clients: \(count)")
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
        broadcaster.broadcastToAllClients { $0.userJailRulesUpdated(self.policyRepository.encodedUserJailRules()) }
    }

    fileprivate func applyUpdateJailRule(_ rule: JailRule) {
        policyRepository.updateJailRule(rule)
        applyJailRulesToFilter()
        broadcaster.broadcastToAllClients { $0.userJailRulesUpdated(self.policyRepository.encodedUserJailRules()) }
    }

    fileprivate func applyRemoveJailRule(ruleID: UUID) {
        policyRepository.removeJailRule(ruleID: ruleID)
        applyJailRulesToFilter()
        broadcaster.broadcastToAllClients { $0.userJailRulesUpdated(self.policyRepository.encodedUserJailRules()) }
    }

    // MARK: - Jailed process query

    fileprivate func activeJailedProcesses() -> [RunningProcessInfo] {
        ProcessEnumerator.enumerate(pids: jailAdapter.activeJailedPIDs())
    }

    // MARK: - Discovery mode

    fileprivate func beginDiscovery() {
        adapter.setDiscoveryPaths(["/Users"])
        logger.info("XPCServer: Discovery mode activated")
    }

    fileprivate func endDiscovery() {
        adapter.setDiscoveryPaths([])
        logger.info("XPCServer: Discovery mode deactivated")
    }

    // MARK: - Signature issue resolution

    fileprivate func resolveSignatureIssue(approved: Bool) {
        policyRepository.resolveSignatureIssue(approved: approved)
        applyPolicyToFilter()
        applyAllowlistToFilter()
        broadcaster.broadcastToAllClients { $0.userRulesUpdated(self.policyRepository.encodedUserRules()) }
        broadcaster.broadcastToAllClients { $0.userAllowlistUpdated(self.policyRepository.encodedUserAllowlist()) }
        let action = approved ? "approved — re-signed" : "rejected — cleared"
        logger.info("XPCServer: Signature issue \(action, privacy: .public) user rules and allowlist")
    }

    // MARK: - Resync

    fileprivate func requestResync(requestingConnection: NSXPCConnection, reply: @escaping () -> Void) {
        Task {
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
        newConnection.remoteObjectInterface = remoteInterface

        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            guard let conn = newConnection else { return }
            self?.removeClient(conn)
        }
        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            guard let conn = newConnection else { return }
            logger.error("XPCServer: Connection interrupted")
            self?.removeClient(conn)
        }

        guard ConnectionValidator.validate(newConnection) else {
            logger.error("XPCServer: Rejected connection — validation failed")
            return false
        }

        newConnection.resume()
        logger.debug("XPCServer: Accepted connection (protocol v\(XPCConstants.protocolVersion, privacy: .public)")
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
        server.addGUIClient(conn)
        reply(true)
    }

    func unregisterClient(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server else { reply(false); return }
        server.removeClient(conn)
        reply(true)
    }

    func fetchRecentEvents(withReply reply: @escaping ([FolderOpenEvent]) -> Void) {
        reply(server?.recentEvents() ?? [])
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
        server.applyAddRule(rule)
        reply(true)
    }

    func updateRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let rule = try? JSONDecoder().decode(FAARule.self, from: ruleData as Data) else {
            reply(false)
            return
        }
        server.applyUpdateRule(rule)
        reply(true)
    }

    func removeRule(_ ruleID: NSUUID, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        server.applyRemoveRule(ruleID: ruleID as UUID)
        reply(true)
    }

    func addAllowlistEntry(_ entryData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let entry = try? JSONDecoder().decode(AllowlistEntry.self, from: entryData as Data) else {
            reply(false)
            return
        }
        server.applyAddAllowlistEntry(entry)
        reply(true)
    }

    func removeAllowlistEntry(_ entryID: NSUUID, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        server.applyRemoveAllowlistEntry(entryID: entryID as UUID)
        reply(true)
    }

    func addAncestorAllowlistEntry(_ entryData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let entry = try? JSONDecoder().decode(AncestorAllowlistEntry.self, from: entryData as Data) else {
            reply(false)
            return
        }
        server.applyAddAncestorAllowlistEntry(entry)
        reply(true)
    }

    func removeAncestorAllowlistEntry(_ entryID: NSUUID, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        server.applyRemoveAncestorAllowlistEntry(entryID: entryID as UUID)
        reply(true)
    }

    func addJailRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let rule = try? JSONDecoder().decode(JailRule.self, from: ruleData as Data) else {
            reply(false)
            return
        }
        server.applyAddJailRule(rule)
        reply(true)
    }

    func updateJailRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let rule = try? JSONDecoder().decode(JailRule.self, from: ruleData as Data) else {
            reply(false)
            return
        }
        server.applyUpdateJailRule(rule)
        reply(true)
    }

    func removeJailRule(_ ruleID: NSUUID, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        server.applyRemoveJailRule(ruleID: ruleID as UUID)
        reply(true)
    }

    func requestResync(withReply reply: @escaping () -> Void) {
        guard let server, let conn = connection else { reply(); return }
        server.requestResync(requestingConnection: conn, reply: reply)
    }

    func beginDiscovery(withReply reply: @escaping () -> Void) {
        server?.beginDiscovery()
        reply()
    }

    func endDiscovery(withReply reply: @escaping () -> Void) {
        server?.endDiscovery()
        reply()
    }

    func fetchProcessList(withReply reply: @escaping ([RunningProcessInfo]) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            reply(ProcessEnumerator.enumerateAll())
        }
    }

    func fetchActiveJailedProcesses(withReply reply: @escaping ([RunningProcessInfo]) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            reply(self?.server?.activeJailedProcesses() ?? [])
        }
    }

    func resolveSignatureIssue(approved: Bool, withReply reply: @escaping () -> Void) {
        server?.resolveSignatureIssue(approved: approved)
        reply()
    }
}

