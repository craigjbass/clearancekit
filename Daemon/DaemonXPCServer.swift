//
//  DaemonXPCServer.swift
//  clearancekit-daemon
//

import Foundation

private let userPolicyDir  = URL(fileURLWithPath: "/Library/Application Support/clearancekit")
private let userPolicyURL  = userPolicyDir.appendingPathComponent("user-policy.json")

final class DaemonXPCServer: NSObject {
    static let shared = DaemonXPCServer()

    private var listener: NSXPCListener?
    private let lock = NSLock()
    private var guiClients: [ObjectIdentifier: NSXPCConnection] = [:]
    private var filterClients: [ObjectIdentifier: NSXPCConnection] = [:]
    private var monitoringActive = false
    private var recentEvents: [FolderOpenEvent] = []
    private var userRules: [FAARule] = []
    private let maxHistoryCount = 1000

    private override init() {
        super.init()
    }

    func start() {
        userRules = loadUserRulesFromDisk()
        listener = NSXPCListener(machServiceName: XPCConstants.daemonServiceName)
        listener?.delegate = self
        listener?.resume()
        NSLog("DaemonXPCServer: Listening on %@", XPCConstants.daemonServiceName)
    }

    // MARK: - Client registration

    fileprivate func addGUIClient(_ connection: NSXPCConnection) {
        lock.lock()
        guiClients[ObjectIdentifier(connection)] = connection
        let count = guiClients.count
        lock.unlock()
        NSLog("DaemonXPCServer: GUI client registered. Active clients: %d", count)
    }

    fileprivate func addFilterClient(_ connection: NSXPCConnection) {
        lock.lock()
        filterClients[ObjectIdentifier(connection)] = connection
        let count = filterClients.count
        lock.unlock()
        NSLog("DaemonXPCServer: Filter client registered. Active filter clients: %d", count)
        // Push current merged policy immediately so the filter is up to date on connect/reconnect.
        (connection.remoteObjectProxy as? FilterClientProtocol)?.policyUpdated(mergedPolicyData())
    }

    fileprivate func removeClient(_ connection: NSXPCConnection) {
        lock.lock()
        guiClients.removeValue(forKey: ObjectIdentifier(connection))
        filterClients.removeValue(forKey: ObjectIdentifier(connection))
        let guiCount = guiClients.count
        let filterCount = filterClients.count
        lock.unlock()
        NSLog("DaemonXPCServer: Client removed. GUI: %d, Filter: %d", guiCount, filterCount)
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
            (conn.remoteObjectProxy as? DaemonClientProtocol)?.folderOpened(event)
        }
    }

    fileprivate func getRecentEvents() -> [FolderOpenEvent] {
        lock.lock()
        defer { lock.unlock() }
        return recentEvents
    }

    fileprivate func broadcastMonitoringStatus(_ isActive: Bool) {
        monitoringActive = isActive
        lock.lock()
        let clients = Array(guiClients.values)
        lock.unlock()
        for conn in clients {
            (conn.remoteObjectProxy as? DaemonClientProtocol)?.monitoringStatusChanged(isActive)
        }
    }

    fileprivate func currentMonitoringStatus() -> Bool {
        monitoringActive
    }

    // MARK: - Rule mutations

    fileprivate func applyAddRule(_ rule: FAARule) {
        lock.lock()
        userRules.append(rule)
        lock.unlock()
        persistAndBroadcast()
    }

    fileprivate func applyUpdateRule(_ rule: FAARule) {
        lock.lock()
        guard let index = userRules.firstIndex(where: { $0.id == rule.id }) else {
            lock.unlock()
            NSLog("DaemonXPCServer: updateRule — rule %@ not found", rule.id.uuidString)
            return
        }
        userRules[index] = rule
        lock.unlock()
        persistAndBroadcast()
    }

    fileprivate func applyRemoveRule(ruleID: UUID) {
        lock.lock()
        userRules.removeAll { $0.id == ruleID }
        lock.unlock()
        persistAndBroadcast()
    }

    private func persistAndBroadcast() {
        saveUserRulesToDisk()
        broadcastMergedPolicyToFilterClients()
        broadcastUserRulesToAllGUIClients()
    }

    // MARK: - Resync

    fileprivate func requestResyncFromFilterClients(requestingConnection: NSXPCConnection) {
        lock.lock()
        let clients = Array(filterClients.values)
        lock.unlock()
        NSLog("DaemonXPCServer: Requesting resync from %d filter client(s)", clients.count)
        for conn in clients {
            (conn.remoteObjectProxy as? FilterClientProtocol)?.resyncStatus()
        }
        pushUserRulesToGUIClient(requestingConnection)
    }

    // MARK: - Policy helpers

    fileprivate func mergedPolicyData() -> NSData {
        // Baseline rules (faaPolicy) are evaluated first and cannot be displaced by user rules.
        guard let data = try? JSONEncoder().encode(faaPolicy + userRules) else {
            fatalError("DaemonXPCServer: Failed to encode merged policy — this is a bug")
        }
        return data as NSData
    }

    private func encodedUserRules() -> NSData {
        guard let data = try? JSONEncoder().encode(userRules) else {
            fatalError("DaemonXPCServer: Failed to encode user rules — this is a bug")
        }
        return data as NSData
    }

    private func broadcastMergedPolicyToFilterClients() {
        let data = mergedPolicyData()
        lock.lock()
        let clients = Array(filterClients.values)
        lock.unlock()
        NSLog("DaemonXPCServer: Broadcasting merged policy to %d filter client(s)", clients.count)
        for conn in clients {
            (conn.remoteObjectProxy as? FilterClientProtocol)?.policyUpdated(data)
        }
    }

    private func broadcastUserRulesToAllGUIClients() {
        let data = encodedUserRules()
        lock.lock()
        let clients = Array(guiClients.values)
        lock.unlock()
        for conn in clients {
            (conn.remoteObjectProxy as? DaemonClientProtocol)?.userRulesUpdated(data)
        }
    }

    fileprivate func pushUserRulesToGUIClient(_ connection: NSXPCConnection) {
        (connection.remoteObjectProxy as? DaemonClientProtocol)?.userRulesUpdated(encodedUserRules())
    }

    // MARK: - Disk I/O

    private func loadUserRulesFromDisk() -> [FAARule] {
        guard let data = try? Data(contentsOf: userPolicyURL) else { return [] }
        guard let rules = try? JSONDecoder().decode([FAARule].self, from: data) else {
            NSLog("DaemonXPCServer: Failed to decode user policy from disk — starting with empty policy")
            return []
        }
        NSLog("DaemonXPCServer: Loaded %d user rule(s) from disk", rules.count)
        return rules
    }

    private func saveUserRulesToDisk() {
        // 0o700: only root can read, write, or list this directory.
        // createDirectory is a no-op if the directory already exists with withIntermediateDirectories: true.
        let dirAttrs: [FileAttributeKey: Any] = [.posixPermissions: 0o700]
        do {
            try FileManager.default.createDirectory(at: userPolicyDir, withIntermediateDirectories: true, attributes: dirAttrs)
        } catch {
            fatalError("DaemonXPCServer: Failed to create policy directory: \(error)")
        }
        guard let data = try? JSONEncoder().encode(userRules) else {
            fatalError("DaemonXPCServer: Failed to encode user rules for disk — this is a bug")
        }
        do {
            // .atomic writes to a temp file then renames, preserving the original on failure.
            // After the write, lock the file down to root read/write only (0o600).
            try data.write(to: userPolicyURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: userPolicyURL.path)
        } catch {
            NSLog("DaemonXPCServer: Failed to write user policy to disk: %@", error.localizedDescription)
        }
    }
}

// MARK: - NSXPCListenerDelegate

extension DaemonXPCServer: NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        let exportedInterface = NSXPCInterface(with: DaemonServiceProtocol.self)
        let eventClasses = NSSet(array: [FolderOpenEvent.self, AncestorInfo.self, NSArray.self, NSDate.self, NSString.self, NSUUID.self]) as! Set<AnyHashable>
        exportedInterface.setClasses(
            eventClasses,
            for: #selector(DaemonServiceProtocol.reportEvent(_:)),
            argumentIndex: 0,
            ofReply: false
        )
        exportedInterface.setClasses(
            eventClasses,
            for: #selector(DaemonServiceProtocol.fetchRecentEvents(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        newConnection.exportedInterface = exportedInterface
        newConnection.exportedObject = ConnectionHandler(server: self, connection: newConnection)

        newConnection.remoteObjectInterface = NSXPCInterface(with: AnyClientProtocol.self)
        newConnection.remoteObjectInterface?.setClasses(
            eventClasses,
            for: #selector(DaemonClientProtocol.folderOpened(_:)),
            argumentIndex: 0,
            ofReply: false
        )

        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            guard let conn = newConnection else { return }
            self?.removeClient(conn)
        }
        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            guard let conn = newConnection else { return }
            NSLog("DaemonXPCServer: Connection interrupted")
            self?.removeClient(conn)
        }

        guard ConnectionValidator.validate(newConnection) else {
            NSLog("DaemonXPCServer: Rejected connection — validation failed")
            return false
        }

        newConnection.resume()
        NSLog("DaemonXPCServer: Accepted connection (protocol v%@)", XPCConstants.protocolVersion)
        return true
    }
}

// MARK: - ConnectionHandler

private final class ConnectionHandler: NSObject, DaemonServiceProtocol {
    weak var server: DaemonXPCServer?
    weak var connection: NSXPCConnection?

    init(server: DaemonXPCServer, connection: NSXPCConnection) {
        self.server = server
        self.connection = connection
        super.init()
    }

    // MARK: Called by GUI app

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

    func isMonitoringActive(withReply reply: @escaping (Bool) -> Void) {
        reply(server?.currentMonitoringStatus() ?? false)
    }

    func fetchRecentEvents(withReply reply: @escaping ([FolderOpenEvent]) -> Void) {
        reply(server?.getRecentEvents() ?? [])
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

    func requestResync(withReply reply: @escaping () -> Void) {
        guard let server, let conn = connection else { reply(); return }
        server.requestResyncFromFilterClients(requestingConnection: conn)
        reply()
    }

    // MARK: Called by opfilter

    func registerFilterClient(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server else { reply(false); return }
        server.addFilterClient(conn)
        reply(true)
    }

    func reportEvent(_ event: FolderOpenEvent) {
        NSLog("DaemonXPCServer: Event from opfilter: %@", event.path)
        server?.broadcastEvent(event)
    }

    func reportMonitoringStatus(_ isActive: Bool) {
        NSLog("DaemonXPCServer: Monitoring status from opfilter: %@", isActive ? "active" : "inactive")
        server?.broadcastMonitoringStatus(isActive)
    }
}
