//
//  XPCServer.swift
//  opfilter
//
//  XPC server that exposes policy management to the GUI app.
//  Replaces the former DaemonXPCServer — opfilter is now the single
//  privileged process for both ES enforcement and GUI communication.
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "xpc-server")

private let dataDirectory = URL(fileURLWithPath: "/Library/Application Support/clearancekit")

final class XPCServer: NSObject, @unchecked Sendable {
    private var listener: NSXPCListener?
    private let lock = NSLock()
    private var guiClients: [ObjectIdentifier: NSXPCConnection] = [:]
    private var recentEvents: [FolderOpenEvent] = []
    private var managedRules: [FAARule] = []
    private var userRules: [FAARule] = []
    private var xprotectEntries: [AllowlistEntry] = []
    private var managedAllowlist: [AllowlistEntry] = []
    private var userAllowlist: [AllowlistEntry] = []
    private var managedAncestorAllowlist: [AncestorAllowlistEntry] = []
    private var userAncestorAllowlist: [AncestorAllowlistEntry] = []
    private var pendingSuspectUserRules: [FAARule]? = nil
    private var pendingSuspectUserAllowlist: [AllowlistEntry]? = nil
    private let maxHistoryCount = 1000
    private let database: Database
    private let interactor: FilterInteractor
    private let adapter: ESInboundAdapter

    init(interactor: FilterInteractor, adapter: ESInboundAdapter) {
        self.interactor = interactor
        self.adapter = adapter
        self.database = Database(directory: dataDirectory)

        switch database.loadUserRulesResult() {
        case .ok(let rules):
            userRules = rules
        case .suspect(let rules):
            userRules = []
            pendingSuspectUserRules = rules
            logger.warning("XPCServer: Signature issue for user_rules — awaiting GUI resolution")
        }

        switch database.loadUserAllowlistResult() {
        case .ok(let entries):
            userAllowlist = entries
        case .suspect(let entries):
            userAllowlist = []
            pendingSuspectUserAllowlist = entries
            logger.warning("XPCServer: Signature issue for user_allowlist — awaiting GUI resolution")
        }

        switch database.loadUserAncestorAllowlistResult() {
        case .ok(let entries):
            userAncestorAllowlist = entries
        case .suspect(let entries):
            userAncestorAllowlist = []
            // Ancestor allowlist entries bypass all policy rules, so tampering is
            // high impact. Silently discard and log — the user will notice that their
            // ancestor entries are gone and can re-add them after investigating.
            logger.warning("XPCServer: Signature issue for user_ancestor_allowlist — discarding \(entries.count) suspect entry/entries")
        }

        managedRules = ManagedPolicyLoader.load()
        managedAllowlist = ManagedAllowlistLoader.load()
        xprotectEntries = enumerateXProtectEntries()
        let xprotectCount = xprotectEntries.count
        logger.info("XPCServer: Discovered \(xprotectCount) XProtect allowlist entry/entries")

        super.init()

        applyPolicyToFilter()
        applyAllowlistToFilter()
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
            lock.lock()
            let currentPaths = Set(xprotectEntries.map(\.processPath))
            let newPaths = Set(reloaded.map(\.processPath))
            guard currentPaths != newPaths else {
                lock.unlock()
                return
            }
            xprotectEntries = reloaded
            lock.unlock()
            applyAllowlistToFilter()
            logger.info("XPCServer: XProtect bundle changed — reloaded \(reloaded.count) entry/entries")
        }
    }

    // MARK: - Direct filter integration

    func handleEvent(_ event: FolderOpenEvent) {
        broadcastEvent(event)
    }

    // MARK: - Policy / allowlist assembly

    func mergedRules() -> [FAARule] {
        lock.lock()
        let managed = managedRules
        let user = userRules
        lock.unlock()
        return faaPolicy + managed + user
    }

    func mergedAllowlist() -> [AllowlistEntry] {
        lock.lock()
        let xprotect = xprotectEntries
        let managed = managedAllowlist
        let user = userAllowlist
        lock.unlock()
        return baselineAllowlist + xprotect + managed + user
    }

    func mergedAncestorAllowlist() -> [AncestorAllowlistEntry] {
        lock.lock()
        let managed = managedAncestorAllowlist
        let user = userAncestorAllowlist
        lock.unlock()
        return managed + user
    }

    private func applyPolicyToFilter() {
        let rules = mergedRules()
        adapter.updatePolicy(rules)
    }

    private func applyAllowlistToFilter() {
        let entries = mergedAllowlist()
        let ancestorEntries = mergedAncestorAllowlist()
        interactor.updateAllowlist(entries)
        interactor.updateAncestorAllowlist(ancestorEntries)
    }

    // MARK: - Client registration

    fileprivate func addGUIClient(_ connection: NSXPCConnection) {
        lock.lock()
        guiClients[ObjectIdentifier(connection)] = connection
        let count = guiClients.count
        let hasIssue = pendingSuspectUserRules != nil || pendingSuspectUserAllowlist != nil
        lock.unlock()
        logger.debug("XPCServer: GUI client registered. Active clients: \(count)")
        if hasIssue {
            pushSignatureIssueTo(connection)
        }
    }

    private func pushSignatureIssueTo(_ connection: NSXPCConnection) {
        lock.lock()
        let suspectRules = pendingSuspectUserRules
        let suspectAllowlist = pendingSuspectUserAllowlist
        lock.unlock()

        guard let rulesData = try? JSONEncoder().encode(suspectRules ?? []),
              let allowlistData = try? JSONEncoder().encode(suspectAllowlist ?? []) else {
            logger.fault("XPCServer: Failed to encode suspect data — cannot push signature issue to GUI")
            return
        }
        let notification = SignatureIssueNotification(
            suspectRulesData: rulesData as NSData,
            suspectAllowlistData: allowlistData as NSData
        )
        (connection.remoteObjectProxy as? ClientProtocol)?.signatureIssueDetected(notification)
    }

    fileprivate func removeClient(_ connection: NSXPCConnection) {
        lock.lock()
        guiClients.removeValue(forKey: ObjectIdentifier(connection))
        let count = guiClients.count
        lock.unlock()
        logger.debug("XPCServer: Client removed. GUI clients: \(count)")
    }

    // MARK: - Event broadcasting

    fileprivate func broadcastEvent(_ event: FolderOpenEvent) {
        lock.lock()
        recentEvents.append(event)
        if recentEvents.count > maxHistoryCount {
            recentEvents.removeFirst(recentEvents.count - maxHistoryCount)
        }
        let clients = Array(guiClients.values)
        lock.unlock()
        for conn in clients {
            (conn.remoteObjectProxy as? ClientProtocol)?.folderOpened(event)
        }
    }

    fileprivate func getRecentEvents() -> [FolderOpenEvent] {
        lock.lock()
        defer { lock.unlock() }
        return recentEvents
    }

    // MARK: - Rule mutations

    fileprivate func applyAddRule(_ rule: FAARule) {
        lock.lock()
        userRules.append(rule)
        lock.unlock()
        persistAndBroadcastRules()
    }

    fileprivate func applyUpdateRule(_ rule: FAARule) {
        lock.lock()
        guard let index = userRules.firstIndex(where: { $0.id == rule.id }) else {
            lock.unlock()
            logger.error("XPCServer: updateRule — rule \(rule.id.uuidString, privacy: .public) not found")
            return
        }
        userRules[index] = rule
        lock.unlock()
        persistAndBroadcastRules()
    }

    fileprivate func applyRemoveRule(ruleID: UUID) {
        lock.lock()
        userRules.removeAll { $0.id == ruleID }
        lock.unlock()
        persistAndBroadcastRules()
    }

    private func persistAndBroadcastRules() {
        database.saveUserRules(userRules)
        applyPolicyToFilter()
        broadcastUserRulesToAllGUIClients()
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

    fileprivate func resolveSignatureIssue(approved: Bool) {
        lock.lock()
        let suspectRules = pendingSuspectUserRules
        let suspectAllowlist = pendingSuspectUserAllowlist
        pendingSuspectUserRules = nil
        pendingSuspectUserAllowlist = nil
        lock.unlock()

        if approved {
            let rules = suspectRules ?? []
            let allowlist = suspectAllowlist ?? []
            applyUserData(rules: rules, allowlist: allowlist)
            logger.info("XPCServer: Signature issue approved — re-signed \(rules.count) rule(s) and \(allowlist.count) allowlist entry/entries")
        } else {
            applyUserData(rules: [], allowlist: [])
            logger.info("XPCServer: Signature issue rejected — cleared user rules and allowlist")
        }

        applyPolicyToFilter()
        applyAllowlistToFilter()
        broadcastUserRulesToAllGUIClients()
        broadcastUserAllowlistToAllGUIClients()
    }

    private func applyUserData(rules: [FAARule], allowlist: [AllowlistEntry]) {
        lock.lock()
        userRules = rules
        userAllowlist = allowlist
        lock.unlock()
        database.saveUserRules(rules)
        database.saveUserAllowlist(allowlist)
    }

    // MARK: - Resync

    fileprivate func requestResync(requestingConnection: NSXPCConnection, reply: @escaping () -> Void) {
        Task {
            let reloaded = ManagedPolicyLoader.loadWithSync()
            let reloadedAllowlist = ManagedAllowlistLoader.loadWithSync()
            let reloadedXProtect = enumerateXProtectEntries()
            lock.lock()
            managedRules = reloaded
            managedAllowlist = reloadedAllowlist
            xprotectEntries = reloadedXProtect
            lock.unlock()

            applyPolicyToFilter()
            applyAllowlistToFilter()

            pushPolicySnapshotToGUIClient(requestingConnection)
            reply()
        }
    }

    // MARK: - Policy helpers

    private func mergedPolicyData() -> NSData {
        guard let data = try? JSONEncoder().encode(mergedRules()) else {
            fatalError("XPCServer: Failed to encode merged policy — this is a bug")
        }
        return data as NSData
    }

    private func encodedManagedRules() -> NSData {
        lock.lock()
        let rules = managedRules
        lock.unlock()
        guard let data = try? JSONEncoder().encode(rules) else {
            fatalError("XPCServer: Failed to encode managed rules — this is a bug")
        }
        return data as NSData
    }

    private func encodedUserRules() -> NSData {
        lock.lock()
        let rules = userRules
        lock.unlock()
        guard let data = try? JSONEncoder().encode(rules) else {
            fatalError("XPCServer: Failed to encode user rules — this is a bug")
        }
        return data as NSData
    }

    private func broadcastUserRulesToAllGUIClients() {
        let data = encodedUserRules()
        lock.lock()
        let clients = Array(guiClients.values)
        lock.unlock()
        for conn in clients {
            (conn.remoteObjectProxy as? ClientProtocol)?.userRulesUpdated(data)
        }
    }

    fileprivate func pushPolicySnapshotToGUIClient(_ connection: NSXPCConnection) {
        let proxy = connection.remoteObjectProxy as? ClientProtocol
        proxy?.managedRulesUpdated(encodedManagedRules())
        proxy?.userRulesUpdated(encodedUserRules())
        proxy?.managedAllowlistUpdated(encodedManagedAllowlist())
        proxy?.userAllowlistUpdated(encodedUserAllowlist())
        proxy?.managedAncestorAllowlistUpdated(encodedManagedAncestorAllowlist())
        proxy?.userAncestorAllowlistUpdated(encodedUserAncestorAllowlist())
    }

    // MARK: - Allowlist mutations

    fileprivate func applyAddAllowlistEntry(_ entry: AllowlistEntry) {
        lock.lock()
        userAllowlist.append(entry)
        lock.unlock()
        persistAndBroadcastAllowlist()
    }

    fileprivate func applyRemoveAllowlistEntry(entryID: UUID) {
        lock.lock()
        userAllowlist.removeAll { $0.id == entryID }
        lock.unlock()
        persistAndBroadcastAllowlist()
    }

    private func persistAndBroadcastAllowlist() {
        database.saveUserAllowlist(userAllowlist)
        applyAllowlistToFilter()
        broadcastUserAllowlistToAllGUIClients()
    }

    // MARK: - Allowlist helpers

    private func encodedManagedAllowlist() -> NSData {
        lock.lock()
        let entries = managedAllowlist
        lock.unlock()
        guard let data = try? JSONEncoder().encode(entries) else {
            fatalError("XPCServer: Failed to encode managed allowlist — this is a bug")
        }
        return data as NSData
    }

    private func encodedUserAllowlist() -> NSData {
        lock.lock()
        let entries = userAllowlist
        lock.unlock()
        guard let data = try? JSONEncoder().encode(entries) else {
            fatalError("XPCServer: Failed to encode user allowlist — this is a bug")
        }
        return data as NSData
    }

    private func broadcastUserAllowlistToAllGUIClients() {
        let data = encodedUserAllowlist()
        lock.lock()
        let clients = Array(guiClients.values)
        lock.unlock()
        for conn in clients {
            (conn.remoteObjectProxy as? ClientProtocol)?.userAllowlistUpdated(data)
        }
    }

    // MARK: - Ancestor allowlist mutations

    fileprivate func applyAddAncestorAllowlistEntry(_ entry: AncestorAllowlistEntry) {
        lock.lock()
        userAncestorAllowlist.append(entry)
        lock.unlock()
        persistAndBroadcastAncestorAllowlist()
    }

    fileprivate func applyRemoveAncestorAllowlistEntry(entryID: UUID) {
        lock.lock()
        userAncestorAllowlist.removeAll { $0.id == entryID }
        lock.unlock()
        persistAndBroadcastAncestorAllowlist()
    }

    private func persistAndBroadcastAncestorAllowlist() {
        database.saveUserAncestorAllowlist(userAncestorAllowlist)
        applyAllowlistToFilter()
        broadcastUserAncestorAllowlistToAllGUIClients()
    }

    // MARK: - Ancestor allowlist helpers

    private func encodedManagedAncestorAllowlist() -> NSData {
        lock.lock()
        let entries = managedAncestorAllowlist
        lock.unlock()
        guard let data = try? JSONEncoder().encode(entries) else {
            fatalError("XPCServer: Failed to encode managed ancestor allowlist — this is a bug")
        }
        return data as NSData
    }

    private func encodedUserAncestorAllowlist() -> NSData {
        lock.lock()
        let entries = userAncestorAllowlist
        lock.unlock()
        guard let data = try? JSONEncoder().encode(entries) else {
            fatalError("XPCServer: Failed to encode user ancestor allowlist — this is a bug")
        }
        return data as NSData
    }

    private func broadcastUserAncestorAllowlistToAllGUIClients() {
        let data = encodedUserAncestorAllowlist()
        lock.lock()
        let clients = Array(guiClients.values)
        lock.unlock()
        for conn in clients {
            (conn.remoteObjectProxy as? ClientProtocol)?.userAncestorAllowlistUpdated(data)
        }
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
        reply(server?.getRecentEvents() ?? [])
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

    func resolveSignatureIssue(approved: Bool, withReply reply: @escaping () -> Void) {
        server?.resolveSignatureIssue(approved: approved)
        reply()
    }
}
