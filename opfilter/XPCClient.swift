//
//  XPCClient.swift
//  opfilter
//
//  Created by Craig J. Bass on 19/02/2026.
//

import Foundation

final class XPCClient: NSObject {
    static let shared = XPCClient()

    var onPolicyUpdate: (([FAARule]) -> Void)?
    var onAllowlistUpdate: (([AllowlistEntry]) -> Void)?

    private var connection: NSXPCConnection?
    private let reconnectInterval: TimeInterval = 5.0

    private override init() {
        super.init()
    }

    func start() {
        guard connection == nil else { return }

        let conn = NSXPCConnection(machServiceName: XPCConstants.daemonServiceName)

        let remoteInterface = NSXPCInterface(with: DaemonServiceProtocol.self)
        let allowedClasses = NSSet(array: [FolderOpenEvent.self, NSDate.self, NSString.self]) as! Set<AnyHashable>
        remoteInterface.setClasses(
            allowedClasses,
            for: #selector(DaemonServiceProtocol.reportEvent(_:)),
            argumentIndex: 0,
            ofReply: false
        )
        conn.remoteObjectInterface = remoteInterface

        conn.exportedInterface = NSXPCInterface(with: FilterClientProtocol.self)
        conn.exportedObject = self

        conn.invalidationHandler = { [weak self] in
            NSLog("XPCClient (opfilter): Connection to daemon invalidated")
            self?.handleDisconnection()
        }
        conn.interruptionHandler = { [weak self] in
            NSLog("XPCClient (opfilter): Connection to daemon interrupted")
            self?.handleDisconnection()
        }

        conn.resume()
        connection = conn
        NSLog("XPCClient (opfilter): Connecting to daemon at %@", XPCConstants.daemonServiceName)

        registerAndFetchPolicy()
    }

    func reportEvent(_ event: FolderOpenEvent) {
        guard let proxy = connection?.remoteObjectProxy as? DaemonServiceProtocol else { return }
        proxy.reportEvent(event)
    }

    func reportMonitoringStatus(_ isActive: Bool) {
        guard let proxy = connection?.remoteObjectProxy as? DaemonServiceProtocol else { return }
        proxy.reportMonitoringStatus(isActive)
    }

    private func handleDisconnection() {
        connection?.invalidate()
        connection = nil
        NSLog("XPCClient (opfilter): Connection lost, scheduling reconnect")
        scheduleReconnect()
    }

    private func scheduleReconnect() {
        DispatchQueue.main.asyncAfter(deadline: .now() + reconnectInterval) { [weak self] in
            self?.start()
        }
    }

    private func registerAndFetchPolicy() {
        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({
            NSLog("XPCClient (opfilter): registerFilterClient error: %@", $0.localizedDescription)
        }) as? DaemonServiceProtocol else { return }

        // Daemon pushes current merged policy immediately after registration via policyUpdated(_:).
        proxy.registerFilterClient(BuildInfo.gitHash as NSString) { success in
            guard success else {
                NSLog("XPCClient (opfilter): Failed to register as filter client")
                return
            }
        }
    }
}

// MARK: - FilterClientProtocol

extension XPCClient: FilterClientProtocol {
    func policyUpdated(_ policyData: NSData) {
        guard let rules = try? JSONDecoder().decode([FAARule].self, from: policyData as Data) else {
            NSLog("XPCClient (opfilter): Failed to decode policy update")
            return
        }
        NSLog("XPCClient (opfilter): Policy updated — %d rule(s)", rules.count)
        onPolicyUpdate?(rules)
    }

    func allowlistUpdated(_ allowlistData: NSData) {
        guard let entries = try? JSONDecoder().decode([AllowlistEntry].self, from: allowlistData as Data) else {
            NSLog("XPCClient (opfilter): Failed to decode allowlist update")
            return
        }
        NSLog("XPCClient (opfilter): Allowlist updated — %d entry/entries", entries.count)
        onAllowlistUpdate?(entries)
    }

    func resyncStatus() {
        NSLog("XPCClient (opfilter): Resync requested — reporting monitoring status")
        reportMonitoringStatus(true)
    }
}
