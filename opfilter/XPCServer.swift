//
//  XPCServer.swift
//  opfilter
//
//  XPC server that exposes policy management to the GUI app.
//  Replaces the former DaemonXPCServer — opfilter is now the single
//  privileged process for both ES enforcement and GUI communication.
//

import Foundation

private let dataDirectory = URL(fileURLWithPath: "/Library/Application Support/clearancekit")

final class XPCServer: NSObject {
    private var listener: NSXPCListener?
    private let lock = NSLock()
    private var guiClients: [ObjectIdentifier: NSXPCConnection] = [:]
    private var recentEvents: [FolderOpenEvent] = []
    private var managedRules: [FAARule] = []
    private var userRules: [FAARule] = []
    private var xprotectEntries: [AllowlistEntry] = []
    private var managedAllowlist: [AllowlistEntry] = []
    private var userAllowlist: [AllowlistEntry] = []
    private let maxHistoryCount = 1000
    private let database: Database
    private let interactor: FilterInteractor
    private let adapter: ESInboundAdapter
    private var xprotectWatcher: XProtectWatcher?

    init(interactor: FilterInteractor, adapter: ESInboundAdapter) {
        self.interactor = interactor
        self.adapter = adapter
        self.database = Database(directory: dataDirectory)

        userRules = database.loadUserRules()
        managedRules = ManagedPolicyLoader.load()
        userAllowlist = database.loadUserAllowlist()
        managedAllowlist = ManagedAllowlistLoader.load()
        xprotectEntries = enumerateXProtectEntries()
        NSLog("XPCServer: Discovered %d XProtect allowlist entry/entries", xprotectEntries.count)

        super.init()

        applyPolicyToFilter()
        applyAllowlistToFilter()
    }

    func start() {
        listener = NSXPCListener(machServiceName: XPCConstants.serviceName)
        listener?.delegate = self
        listener?.resume()
        NSLog("XPCServer: Listening on %@", XPCConstants.serviceName)

        let watcher = XProtectWatcher { [weak self] in self?.handleXProtectChange() }
        watcher.start()
        xprotectWatcher = watcher
    }

    private func handleXProtectChange() {
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
        NSLog("XPCServer: XProtect bundle changed — reloaded %d entry/entries", reloaded.count)
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

    private func applyPolicyToFilter() {
        let rules = mergedRules()
        adapter.updatePolicy(rules)
    }

    private func applyAllowlistToFilter() {
        let entries = mergedAllowlist()
        interactor.updateAllowlist(entries)
    }

    // MARK: - Client registration

    fileprivate func addGUIClient(_ connection: NSXPCConnection) {
        lock.lock()
        guiClients[ObjectIdentifier(connection)] = connection
        let count = guiClients.count
        lock.unlock()
        NSLog("XPCServer: GUI client registered. Active clients: %d", count)
    }

    fileprivate func removeClient(_ connection: NSXPCConnection) {
        lock.lock()
        guiClients.removeValue(forKey: ObjectIdentifier(connection))
        let count = guiClients.count
        lock.unlock()
        NSLog("XPCServer: Client removed. GUI clients: %d", count)
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
            NSLog("XPCServer: updateRule — rule %@ not found", rule.id.uuidString)
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

    // MARK: - Resync

    fileprivate func requestResync(requestingConnection: NSXPCConnection) {
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
        newConnection.remoteObjectInterface = remoteInterface

        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            guard let conn = newConnection else { return }
            self?.removeClient(conn)
        }
        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            guard let conn = newConnection else { return }
            NSLog("XPCServer: Connection interrupted")
            self?.removeClient(conn)
        }

        guard ConnectionValidator.validate(newConnection) else {
            NSLog("XPCServer: Rejected connection — validation failed")
            return false
        }

        newConnection.resume()
        NSLog("XPCServer: Accepted connection (protocol v%@)", XPCConstants.protocolVersion)
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

    func requestResync(withReply reply: @escaping () -> Void) {
        guard let server, let conn = connection else { reply(); return }
        server.requestResync(requestingConnection: conn)
        reply()
    }

    func fetchProcessList(withReply reply: @escaping ([RunningProcessInfo]) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            reply(ProcessEnumerator.enumerateAll())
        }
    }
}
