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
    private var monitoringActive = false

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

    fileprivate func removeGUIClient(_ connection: NSXPCConnection) {
        lock.lock()
        guiClients.removeValue(forKey: ObjectIdentifier(connection))
        let count = guiClients.count
        lock.unlock()
        NSLog("DaemonXPCServer: GUI client removed. Active clients: %d", count)
    }

    fileprivate func broadcastEvent(_ event: FolderOpenEvent) {
        lock.lock()
        let clients = Array(guiClients.values)
        lock.unlock()
        for conn in clients {
            (conn.remoteObjectProxy as? DaemonClientProtocol)?.folderOpened(event)
        }
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
}

// MARK: - NSXPCListenerDelegate

extension DaemonXPCServer: NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        let exportedInterface = NSXPCInterface(with: DaemonServiceProtocol.self)
        let allowedClasses = NSSet(array: [FolderOpenEvent.self, NSDate.self, NSString.self]) as! Set<AnyHashable>
        exportedInterface.setClasses(
            allowedClasses,
            for: #selector(DaemonServiceProtocol.reportEvent(_:)),
            argumentIndex: 0,
            ofReply: false
        )
        newConnection.exportedInterface = exportedInterface
        newConnection.exportedObject = ConnectionHandler(server: self, connection: newConnection)

        newConnection.remoteObjectInterface = NSXPCInterface(with: DaemonClientProtocol.self)
        let callbackAllowedClasses = NSSet(array: [FolderOpenEvent.self, NSDate.self, NSString.self]) as! Set<AnyHashable>
        newConnection.remoteObjectInterface?.setClasses(
            callbackAllowedClasses,
            for: #selector(DaemonClientProtocol.folderOpened(_:)),
            argumentIndex: 0,
            ofReply: false
        )

        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            guard let conn = newConnection else { return }
            self?.removeGUIClient(conn)
        }
        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            guard let conn = newConnection else { return }
            NSLog("DaemonXPCServer: Connection interrupted")
            self?.removeGUIClient(conn)
        }

        newConnection.resume()
        NSLog("DaemonXPCServer: Accepted new connection")
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
        server.removeGUIClient(conn)
        reply(true)
    }

    func isMonitoringActive(withReply reply: @escaping (Bool) -> Void) {
        reply(server?.currentMonitoringStatus() ?? false)
    }

    // MARK: Called by opfilter

    func reportEvent(_ event: FolderOpenEvent) {
        NSLog("DaemonXPCServer: Event from opfilter: %@", event.path)
        server?.broadcastEvent(event)
    }

    func reportMonitoringStatus(_ isActive: Bool) {
        NSLog("DaemonXPCServer: Monitoring status from opfilter: %@", isActive ? "active" : "inactive")
        server?.broadcastMonitoringStatus(isActive)
    }
}
