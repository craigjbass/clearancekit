//
//  XPCClient.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation
import Combine

@MainActor
final class XPCClient: NSObject, ObservableObject {
    static let shared = XPCClient()

    @Published private(set) var isConnected = false
    @Published private(set) var isMonitoringActive = false
    @Published private(set) var events: [FolderOpenEvent] = []

    private var connection: NSXPCConnection?
    private var clientListener: NSXPCListener?
    private var reconnectTimer: Timer?
    private let reconnectInterval: TimeInterval = 5.0

    private override init() {
        super.init()
    }

    func connect() {
        guard connection == nil else { return }

        NSLog("XPCClient: Connecting to %@", XPCConstants.machServiceName)

        let conn = NSXPCConnection(machServiceName: XPCConstants.machServiceName, options: [])
        conn.remoteObjectInterface = NSXPCInterface(with: OpFilterServiceProtocol.self)

        conn.exportedInterface = NSXPCInterface(with: OpFilterClientProtocol.self)
        conn.exportedObject = self

        let allowedClasses = NSSet(array: [FolderOpenEvent.self, NSDate.self, NSString.self]) as! Set<AnyHashable>
        conn.exportedInterface?.setClasses(
            allowedClasses,
            for: #selector(OpFilterClientProtocol.folderOpened(_:)),
            argumentIndex: 0,
            ofReply: false
        )

        conn.invalidationHandler = { [weak self] in
            Task { @MainActor in
                self?.handleDisconnection()
            }
        }

        conn.interruptionHandler = { [weak self] in
            Task { @MainActor in
                NSLog("XPCClient: Connection interrupted")
                self?.handleDisconnection()
            }
        }

        conn.resume()
        connection = conn

        guard let service = conn.remoteObjectProxyWithErrorHandler({ [weak self] error in
            NSLog("XPCClient: Remote object error: %@", error.localizedDescription)
            Task { @MainActor in
                self?.handleDisconnection()
            }
        }) as? OpFilterServiceProtocol else {
            NSLog("XPCClient: Failed to get remote object proxy")
            handleDisconnection()
            return
        }

        service.registerClient { [weak self] success in
            Task { @MainActor in
                if success {
                    NSLog("XPCClient: Successfully registered with server")
                    self?.isConnected = true
                    self?.stopReconnectTimer()
                    self?.checkMonitoringStatus()
                } else {
                    NSLog("XPCClient: Failed to register with server")
                    self?.handleDisconnection()
                }
            }
        }
    }

    func disconnect() {
        stopReconnectTimer()

        if let conn = connection,
           let service = conn.remoteObjectProxy as? OpFilterServiceProtocol {
            service.unregisterClient { _ in }
        }

        connection?.invalidate()
        connection = nil
        isConnected = false
        isMonitoringActive = false
        NSLog("XPCClient: Disconnected")
    }

    private func handleDisconnection() {
        connection?.invalidate()
        connection = nil
        isConnected = false
        isMonitoringActive = false
        NSLog("XPCClient: Connection lost, scheduling reconnect")
        scheduleReconnect()
    }

    private func scheduleReconnect() {
        guard reconnectTimer == nil else { return }

        reconnectTimer = Timer.scheduledTimer(withTimeInterval: reconnectInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.connect()
            }
        }
    }

    private func stopReconnectTimer() {
        reconnectTimer?.invalidate()
        reconnectTimer = nil
    }

    private func checkMonitoringStatus() {
        guard let conn = connection,
              let service = conn.remoteObjectProxy as? OpFilterServiceProtocol else {
            return
        }

        service.isMonitoringActive { [weak self] isActive in
            Task { @MainActor in
                self?.isMonitoringActive = isActive
            }
        }
    }

    func clearEvents() {
        events.removeAll()
    }
}

// MARK: - OpFilterClientProtocol

extension XPCClient: OpFilterClientProtocol {
    nonisolated func folderOpened(_ event: FolderOpenEvent) {
        NSLog("XPCClient: Received folder open event: %@", event.path)
        Task { @MainActor in
            self.events.insert(event, at: 0)
        }
    }

    nonisolated func monitoringStatusChanged(_ isActive: Bool) {
        NSLog("XPCClient: Monitoring status changed: %@", isActive ? "active" : "inactive")
        Task { @MainActor in
            self.isMonitoringActive = isActive
        }
    }
}
