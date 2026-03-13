//
//  DaemonXPCServer.swift
//  clearancekit-daemon
//
//  Created by Craig J. Bass on 19/02/2026.
//

import Foundation

final class DaemonXPCServer: NSObject {
    static let shared = DaemonXPCServer()

    private var listener: NSXPCListener?
    private let lock = NSLock()
    private var guiClients: [ObjectIdentifier: NSXPCConnection] = [:]
    private var filterClients: [ObjectIdentifier: NSXPCConnection] = [:]
    private var monitoringActive = false
    private var recentEvents: [FolderOpenEvent] = []
    private var currentPolicyData: NSData?
    private let maxHistoryCount = 1000

    private override init() {
        super.init()
    }

    func start() {
        listener = NSXPCListener(machServiceName: XPCConstants.daemonServiceName)
        listener?.delegate = self
        listener?.resume()
        NSLog("DaemonXPCServer: Listening on %@", XPCConstants.daemonServiceName)
    }

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
        NSLog("DaemonXPCServer: Filter client registered. Active clients: %d", count)
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

    fileprivate func storeAndBroadcastPolicy(_ policyData: NSData) {
        lock.lock()
        currentPolicyData = policyData
        let clients = Array(filterClients.values)
        lock.unlock()
        NSLog("DaemonXPCServer: Broadcasting policy to %d filter client(s)", clients.count)
        for conn in clients {
            (conn.remoteObjectProxy as? FilterClientProtocol)?.policyUpdated(policyData)
        }
    }

    fileprivate func getCurrentPolicy() -> NSData {
        lock.lock()
        defer { lock.unlock() }
        return currentPolicyData ?? NSData()
    }

    fileprivate func requestResyncFromFilterClients() {
        lock.lock()
        let clients = Array(filterClients.values)
        lock.unlock()
        NSLog("DaemonXPCServer: Requesting resync from %d filter client(s)", clients.count)
        for conn in clients {
            (conn.remoteObjectProxy as? FilterClientProtocol)?.resyncStatus()
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

        // remoteObjectInterface must be AnyClientProtocol so the daemon can call back
        // to both GUI connections (DaemonClientProtocol) and opfilter connections
        // (FilterClientProtocol) through the same accepted connection.
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
        guard let conn = connection, let server = server else {
            reply(false)
            return
        }
        server.addGUIClient(conn)
        reply(true)
    }

    func unregisterClient(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server = server else {
            reply(false)
            return
        }
        server.removeClient(conn)
        reply(true)
    }

    func isMonitoringActive(withReply reply: @escaping (Bool) -> Void) {
        reply(server?.currentMonitoringStatus() ?? false)
    }

    func fetchRecentEvents(withReply reply: @escaping ([FolderOpenEvent]) -> Void) {
        reply(server?.getRecentEvents() ?? [])
    }

    func updatePolicy(_ policyData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server = server else {
            reply(false)
            return
        }
        server.storeAndBroadcastPolicy(policyData)
        reply(true)
    }

    func fetchCurrentPolicy(withReply reply: @escaping (NSData) -> Void) {
        reply(server?.getCurrentPolicy() ?? NSData())
    }

    // MARK: Called by opfilter

    func registerFilterClient(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server = server else {
            reply(false)
            return
        }
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

    func requestResync(withReply reply: @escaping () -> Void) {
        server?.requestResyncFromFilterClients()
        reply()
    }
}
