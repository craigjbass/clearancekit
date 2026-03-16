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
    @Published private(set) var hasServiceVersionMismatch = false
    @Published private(set) var serviceVersion = ""
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

        NSLog("XPCClient: Connecting to %@", XPCConstants.serviceName)

        let conn = NSXPCConnection(machServiceName: XPCConstants.serviceName, options: [])
        let eventClasses = NSSet(array: [FolderOpenEvent.self, AncestorInfo.self, NSArray.self, NSDate.self, NSString.self, NSUUID.self]) as! Set<AnyHashable>

        let remoteInterface = NSXPCInterface(with: ServiceProtocol.self)
        remoteInterface.setClasses(
            eventClasses,
            for: #selector(ServiceProtocol.fetchRecentEvents(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        let processInfoClasses = NSSet(array: [NSArray.self, RunningProcessInfo.self]) as! Set<AnyHashable>
        remoteInterface.setClasses(
            processInfoClasses,
            for: #selector(ServiceProtocol.fetchProcessList(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        conn.remoteObjectInterface = remoteInterface

        conn.exportedInterface = NSXPCInterface(with: ClientProtocol.self)
        conn.exportedObject = self

        conn.exportedInterface?.setClasses(
            eventClasses,
            for: #selector(ClientProtocol.folderOpened(_:)),
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
        }) as? ServiceProtocol else {
            NSLog("XPCClient: Failed to get remote object proxy")
            handleDisconnection()
            return
        }

        service.registerClient { [weak self] success in
            Task { @MainActor in
                if success {
                    NSLog("XPCClient: Successfully registered with service")
                    self?.isConnected = true
                    self?.hasServiceVersionMismatch = false
                    self?.stopReconnectTimer()
                    self?.fetchVersionInfo()
                    self?.requestResync()
                } else {
                    NSLog("XPCClient: Failed to register with service")
                    self?.handleDisconnection()
                }
            }
        }
    }

    func disconnect() {
        stopReconnectTimer()

        if let conn = connection,
           let service = conn.remoteObjectProxy as? ServiceProtocol {
            service.unregisterClient { _ in }
        }

        connection?.invalidate()
        connection = nil
        isConnected = false

        NSLog("XPCClient: Disconnected")
    }

    private func handleDisconnection() {
        connection?.invalidate()
        connection = nil
        isConnected = false

        NSLog("XPCClient: Connection lost, scheduling reconnect")
        scheduleReconnect()
    }

    private func handleServiceVersionMismatch() {
        hasServiceVersionMismatch = true
        connection?.invalidate()
        connection = nil
        isConnected = false

        stopReconnectTimer()
        NSLog("XPCClient: Service version mismatch — stopped reconnecting. Reactivate the system extension to resolve.")
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

    private func fetchVersionInfo() {
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: fetchVersionInfo error: %@", error.localizedDescription)
        }) as? ServiceProtocol else { return }

        service.fetchVersionInfo { [weak self] version in
            Task { @MainActor in
                self?.serviceVersion = version as String
                NSLog("XPCClient: service v%@", version)
            }
        }
    }

    func requestResync() {
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: requestResync error: %@", error.localizedDescription)
        }) as? ServiceProtocol else { return }

        service.requestResync { }
    }

    // MARK: - Rule mutations

    func addRule(_ rule: FAARule) {
        guard let data = try? JSONEncoder().encode(rule) else { return }
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: addRule error: %@", error.localizedDescription)
        }) as? ServiceProtocol else { return }
        service.addRule(data as NSData) { success in
            if !success { NSLog("XPCClient: addRule rejected by service") }
        }
    }

    func updateRule(_ rule: FAARule) {
        guard let data = try? JSONEncoder().encode(rule) else { return }
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: updateRule error: %@", error.localizedDescription)
        }) as? ServiceProtocol else { return }
        service.updateRule(data as NSData) { success in
            if !success { NSLog("XPCClient: updateRule rejected by service") }
        }
    }

    func removeRule(ruleID: UUID) {
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: removeRule error: %@", error.localizedDescription)
        }) as? ServiceProtocol else { return }
        service.removeRule(ruleID as NSUUID) { success in
            if !success { NSLog("XPCClient: removeRule rejected by service") }
        }
    }

    // MARK: - Allowlist mutations

    func addAllowlistEntry(_ entry: AllowlistEntry) {
        guard let data = try? JSONEncoder().encode(entry) else { return }
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: addAllowlistEntry error: %@", error.localizedDescription)
        }) as? ServiceProtocol else { return }
        service.addAllowlistEntry(data as NSData) { success in
            if !success { NSLog("XPCClient: addAllowlistEntry rejected by service") }
        }
    }

    func removeAllowlistEntry(entryID: UUID) {
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: removeAllowlistEntry error: %@", error.localizedDescription)
        }) as? ServiceProtocol else { return }
        service.removeAllowlistEntry(entryID as NSUUID) { success in
            if !success { NSLog("XPCClient: removeAllowlistEntry rejected by service") }
        }
    }

    // MARK: - Process list

    func fetchProcessList() async -> [RunningProcessInfo] {
        await withCheckedContinuation { continuation in
            guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
                NSLog("XPCClient: fetchProcessList error: %@", error.localizedDescription)
                continuation.resume(returning: [])
            }) as? ServiceProtocol else {
                continuation.resume(returning: [])
                return
            }
            service.fetchProcessList { processes in
                continuation.resume(returning: processes)
            }
        }
    }

    // MARK: - Discovery mode

    func beginDiscovery() {
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: beginDiscovery error: %@", error.localizedDescription)
        }) as? ServiceProtocol else { return }
        service.beginDiscovery { }
    }

    func endDiscovery() {
        guard let service = connection?.remoteObjectProxyWithErrorHandler({ error in
            NSLog("XPCClient: endDiscovery error: %@", error.localizedDescription)
        }) as? ServiceProtocol else { return }
        service.endDiscovery { }
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
              }) as? ServiceProtocol else {
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

// MARK: - ClientProtocol

extension XPCClient: ClientProtocol {
    nonisolated func folderOpened(_ event: FolderOpenEvent) {
        NSLog("XPCClient: Received folder open event: %@", event.path)
        Task { @MainActor in
            self.events.insert(event, at: 0)
            if !event.accessAllowed {
                self.sendDenyNotificationIfNeeded(for: event)
            }
        }
    }

    nonisolated func managedRulesUpdated(_ rulesData: NSData) {
        guard let rules = try? JSONDecoder().decode([FAARule].self, from: rulesData as Data) else {
            NSLog("XPCClient: Failed to decode managed rules — version mismatch, invalidating connection")
            Task { @MainActor in self.handleServiceVersionMismatch() }
            return
        }
        Task { @MainActor in
            PolicyStore.shared.receivedManagedRules(rules)
        }
    }

    nonisolated func userRulesUpdated(_ rulesData: NSData) {
        guard let rules = try? JSONDecoder().decode([FAARule].self, from: rulesData as Data) else {
            NSLog("XPCClient: Failed to decode user rules — version mismatch, invalidating connection")
            Task { @MainActor in self.handleServiceVersionMismatch() }
            return
        }
        Task { @MainActor in
            PolicyStore.shared.receivedUserRules(rules)
        }
    }

    nonisolated func managedAllowlistUpdated(_ allowlistData: NSData) {
        guard let entries = try? JSONDecoder().decode([AllowlistEntry].self, from: allowlistData as Data) else {
            NSLog("XPCClient: Failed to decode managed allowlist — version mismatch, invalidating connection")
            Task { @MainActor in self.handleServiceVersionMismatch() }
            return
        }
        Task { @MainActor in
            AllowlistStore.shared.receivedManagedEntries(entries)
        }
    }

    nonisolated func userAllowlistUpdated(_ allowlistData: NSData) {
        guard let entries = try? JSONDecoder().decode([AllowlistEntry].self, from: allowlistData as Data) else {
            NSLog("XPCClient: Failed to decode user allowlist — version mismatch, invalidating connection")
            Task { @MainActor in self.handleServiceVersionMismatch() }
            return
        }
        Task { @MainActor in
            AllowlistStore.shared.receivedUserEntries(entries)
        }
    }
}
