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
    private var reconnectTimer: Timer?
    private let reconnectInterval: TimeInterval = 5.0

    private override init() {
        super.init()
    }

    func connect() {
        guard connection == nil else { return }

        NSLog("XPCClient: Connecting to %@", XPCConstants.daemonServiceName)

        let conn = NSXPCConnection(machServiceName: XPCConstants.daemonServiceName, options: [])
        let eventClasses = NSSet(array: [FolderOpenEvent.self, AncestorInfo.self, NSArray.self, NSDate.self, NSString.self, NSUUID.self]) as! Set<AnyHashable>

        let remoteInterface = NSXPCInterface(with: DaemonServiceProtocol.self)
        remoteInterface.setClasses(
            eventClasses,
            for: #selector(DaemonServiceProtocol.fetchRecentEvents(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        conn.remoteObjectInterface = remoteInterface

        conn.exportedInterface = NSXPCInterface(with: DaemonClientProtocol.self)
        conn.exportedObject = self

        conn.exportedInterface?.setClasses(
            eventClasses,
            for: #selector(DaemonClientProtocol.folderOpened(_:)),
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
        }) as? DaemonServiceProtocol else {
            NSLog("XPCClient: Failed to get remote object proxy")
            handleDisconnection()
            return
        }

        service.registerClient { [weak self] success in
            Task { @MainActor in
                if success {
                    NSLog("XPCClient: Successfully registered with daemon")
                    self?.isConnected = true
                    self?.stopReconnectTimer()
                    self?.checkMonitoringStatus()
                } else {
                    NSLog("XPCClient: Failed to register with daemon")
                    self?.handleDisconnection()
                }
            }
        }
    }

    func disconnect() {
        stopReconnectTimer()

        if let conn = connection,
           let service = conn.remoteObjectProxy as? DaemonServiceProtocol {
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
              let service = conn.remoteObjectProxy as? DaemonServiceProtocol else {
            return
        }

        service.isMonitoringActive { [weak self] isActive in
            Task { @MainActor in
                self?.isMonitoringActive = isActive
            }
        }
    }

    func updatePolicy(rules: [FAARule]) {
        guard let data = try? JSONEncoder().encode(rules) else { return }
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: updatePolicy error: %@", error.localizedDescription)
        }) as? DaemonServiceProtocol else { return }
        service.updatePolicy(data as NSData) { success in
            NSLog("XPCClient: Policy update %@", success ? "succeeded" : "failed")
        }
    }

    func clearEvents() {
        events.removeAll()
    }

    func fetchHistoricEvents() {
        guard let conn = connection,
              let service = conn.remoteObjectProxyWithErrorHandler({ error in
                  NSLog("XPCClient: fetchHistoricEvents error: %@", error.localizedDescription)
              }) as? DaemonServiceProtocol else {
            return
        }
        service.fetchRecentEvents { [weak self] historicEvents in
            Task { @MainActor in
                guard let self = self else { return }
                let existingIDs = Set(self.events.map(\.eventID))
                let newEvents = historicEvents.filter { !existingIDs.contains($0.eventID) }
                self.events.append(contentsOf: newEvents)
                self.events.sort { $0.timestamp > $1.timestamp }
            }
        }
    }
}

// MARK: - DaemonClientProtocol

extension XPCClient: DaemonClientProtocol {
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
