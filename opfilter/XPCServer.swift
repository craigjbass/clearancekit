//
//  XPCServer.swift
//  opfilter
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation

final class XPCServer: NSObject {
    static let shared = XPCServer()

    private var listener: NSXPCListener?
    private let clientsLock = NSLock()
    private var clients: [ObjectIdentifier: NSXPCConnection] = [:]

    private override init() {
        super.init()
    }

    func start() {
        listener = NSXPCListener(machServiceName: XPCConstants.machServiceName)
        listener?.delegate = self
        listener?.resume()
        NSLog("XPCServer: Started listening on %@", XPCConstants.machServiceName)
    }

    func broadcastEvent(_ event: FolderOpenEvent) {
        clientsLock.lock()
        let activeClients = clients.values
        clientsLock.unlock()

        for connection in activeClients {
            guard let client = connection.remoteObjectProxy as? OpFilterClientProtocol else {
                continue
            }
            client.folderOpened(event)
        }
    }

    func broadcastMonitoringStatus(_ isActive: Bool) {
        clientsLock.lock()
        let activeClients = clients.values
        clientsLock.unlock()

        for connection in activeClients {
            guard let client = connection.remoteObjectProxy as? OpFilterClientProtocol else {
                continue
            }
            client.monitoringStatusChanged(isActive)
        }
    }

    private func removeClient(_ connection: NSXPCConnection) {
        clientsLock.lock()
        clients.removeValue(forKey: ObjectIdentifier(connection))
        let count = clients.count
        clientsLock.unlock()
        NSLog("XPCServer: Client disconnected. Active clients: %d", count)
    }
}

// MARK: - NSXPCListenerDelegate

extension XPCServer: NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: OpFilterServiceProtocol.self)
        newConnection.exportedObject = ConnectionHandler(server: self, connection: newConnection)

        newConnection.remoteObjectInterface = NSXPCInterface(with: OpFilterClientProtocol.self)

        let allowedClasses = NSSet(array: [FolderOpenEvent.self, NSDate.self, NSString.self]) as! Set<AnyHashable>
        newConnection.remoteObjectInterface?.setClasses(
            allowedClasses as! Set<AnyHashable>,
            for: #selector(OpFilterClientProtocol.folderOpened(_:)),
            argumentIndex: 0,
            ofReply: false
        )

        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            guard let connection = newConnection else { return }
            self?.removeClient(connection)
        }

        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            guard let connection = newConnection else { return }
            NSLog("XPCServer: Connection interrupted")
            self?.removeClient(connection)
        }

        clientsLock.lock()
        clients[ObjectIdentifier(newConnection)] = newConnection
        let count = clients.count
        clientsLock.unlock()

        newConnection.resume()
        NSLog("XPCServer: Accepted new connection. Active clients: %d", count)
        return true
    }
}

// MARK: - ConnectionHandler

private final class ConnectionHandler: NSObject, OpFilterServiceProtocol {
    weak var server: XPCServer?
    weak var connection: NSXPCConnection?

    init(server: XPCServer, connection: NSXPCConnection) {
        self.server = server
        self.connection = connection
        super.init()
    }

    func registerClient(withReply reply: @escaping (Bool) -> Void) {
        NSLog("XPCServer: Client registered")
        reply(true)
    }

    func unregisterClient(withReply reply: @escaping (Bool) -> Void) {
        NSLog("XPCServer: Client unregistered")
        reply(true)
    }

    func isMonitoringActive(withReply reply: @escaping (Bool) -> Void) {
        reply(true)
    }
}
