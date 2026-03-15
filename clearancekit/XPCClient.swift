//
//  XPCClient.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import Foundation
import Combine
import UserNotifications

@MainActor
final class XPCClient: NSObject, ObservableObject {
    static let shared = XPCClient()

    @Published private(set) var isConnected = false
    @Published private(set) var isMonitoringActive = false
    @Published private(set) var events: [FolderOpenEvent] = []

    private var connection: NSXPCConnection?
    private var reconnectTimer: Timer?
    private let reconnectInterval: TimeInterval = 5.0
    private var lastDenyNotificationDate: Date?
    private let denyNotificationDebounce: TimeInterval = 30.0

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
        let processInfoClasses = NSSet(array: [NSArray.self, RunningProcessInfo.self]) as! Set<AnyHashable>
        remoteInterface.setClasses(
            processInfoClasses,
            for: #selector(DaemonServiceProtocol.fetchProcessList(withReply:)),
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
                    self?.requestResync()
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

    func requestResync() {
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: requestResync error: %@", error.localizedDescription)
        }) as? DaemonServiceProtocol else { return }

        service.requestResync { }
    }

    // MARK: - Rule mutations

    func addRule(_ rule: FAARule) {
        guard let data = try? JSONEncoder().encode(rule) else { return }
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: addRule error: %@", error.localizedDescription)
        }) as? DaemonServiceProtocol else { return }
        service.addRule(data as NSData) { success in
            if !success { NSLog("XPCClient: addRule rejected by daemon") }
        }
    }

    func updateRule(_ rule: FAARule) {
        guard let data = try? JSONEncoder().encode(rule) else { return }
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: updateRule error: %@", error.localizedDescription)
        }) as? DaemonServiceProtocol else { return }
        service.updateRule(data as NSData) { success in
            if !success { NSLog("XPCClient: updateRule rejected by daemon") }
        }
    }

    func removeRule(ruleID: UUID) {
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: removeRule error: %@", error.localizedDescription)
        }) as? DaemonServiceProtocol else { return }
        service.removeRule(ruleID as NSUUID) { success in
            if !success { NSLog("XPCClient: removeRule rejected by daemon") }
        }
    }

    // MARK: - Allowlist mutations

    func addAllowlistEntry(_ entry: AllowlistEntry) {
        guard let data = try? JSONEncoder().encode(entry) else { return }
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: addAllowlistEntry error: %@", error.localizedDescription)
        }) as? DaemonServiceProtocol else { return }
        service.addAllowlistEntry(data as NSData) { success in
            if !success { NSLog("XPCClient: addAllowlistEntry rejected by daemon") }
        }
    }

    func removeAllowlistEntry(entryID: UUID) {
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: removeAllowlistEntry error: %@", error.localizedDescription)
        }) as? DaemonServiceProtocol else { return }
        service.removeAllowlistEntry(entryID as NSUUID) { success in
            if !success { NSLog("XPCClient: removeAllowlistEntry rejected by daemon") }
        }
    }

    // MARK: - Process list

    func fetchProcessList() async -> [RunningProcessInfo] {
        await withCheckedContinuation { continuation in
            guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
                NSLog("XPCClient: fetchProcessList error: %@", error.localizedDescription)
                continuation.resume(returning: [])
            }) as? DaemonServiceProtocol else {
                continuation.resume(returning: [])
                return
            }
            service.fetchProcessList { processes in
                continuation.resume(returning: processes)
            }
        }
    }

    // MARK: - Events

    private func sendDenyNotificationIfNeeded(for event: FolderOpenEvent) {
        let now = Date()
        if let last = lastDenyNotificationDate, now.timeIntervalSince(last) < denyNotificationDebounce {
            return
        }
        lastDenyNotificationDate = now

        let content = UNMutableNotificationContent()
        content.title = "Access Denied"
        content.body = "\(event.processPath.split(separator: "/").last.map(String.init) ?? event.processPath) was blocked from accessing \(event.path)"
        content.sound = .default

        content.userInfo = ["eventID": event.eventID.uuidString]
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { error in
            if let error { NSLog("XPCClient: notification error: %@", error.localizedDescription) }
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
            if !event.accessAllowed {
                self.sendDenyNotificationIfNeeded(for: event)
            }
        }
    }

    nonisolated func monitoringStatusChanged(_ isActive: Bool) {
        NSLog("XPCClient: Monitoring status changed: %@", isActive ? "active" : "inactive")
        Task { @MainActor in
            self.isMonitoringActive = isActive
        }
    }

    nonisolated func managedRulesUpdated(_ rulesData: NSData) {
        guard let rules = try? JSONDecoder().decode([FAARule].self, from: rulesData as Data) else {
            fatalError("XPCClient: Failed to decode managed rules from daemon — binary version mismatch")
        }
        Task { @MainActor in
            PolicyStore.shared.receivedManagedRules(rules)
        }
    }

    nonisolated func userRulesUpdated(_ rulesData: NSData) {
        guard let rules = try? JSONDecoder().decode([FAARule].self, from: rulesData as Data) else {
            fatalError("XPCClient: Failed to decode user rules from daemon — binary version mismatch")
        }
        Task { @MainActor in
            PolicyStore.shared.receivedUserRules(rules)
        }
    }

    nonisolated func managedAllowlistUpdated(_ allowlistData: NSData) {
        guard let entries = try? JSONDecoder().decode([AllowlistEntry].self, from: allowlistData as Data) else {
            fatalError("XPCClient: Failed to decode managed allowlist from daemon — binary version mismatch")
        }
        Task { @MainActor in
            AllowlistStore.shared.receivedManagedEntries(entries)
        }
    }

    nonisolated func userAllowlistUpdated(_ allowlistData: NSData) {
        guard let entries = try? JSONDecoder().decode([AllowlistEntry].self, from: allowlistData as Data) else {
            fatalError("XPCClient: Failed to decode user allowlist from daemon — binary version mismatch")
        }
        Task { @MainActor in
            AllowlistStore.shared.receivedUserEntries(entries)
        }
    }
}
