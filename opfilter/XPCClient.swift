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

    private var connection: NSXPCConnection?

    private override init() {
        super.init()
    }

    func start() {
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

        conn.invalidationHandler = {
            NSLog("XPCClient (opfilter): Connection to daemon invalidated")
        }
        conn.interruptionHandler = {
            NSLog("XPCClient (opfilter): Connection to daemon interrupted")
        }

        conn.resume()
        connection = conn
        NSLog("XPCClient (opfilter): Connected to daemon at %@", XPCConstants.daemonServiceName)

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

    private func registerAndFetchPolicy() {
        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({
            NSLog("XPCClient (opfilter): registerFilterClient error: %@", $0.localizedDescription)
        }) as? DaemonServiceProtocol else { return }

        proxy.registerFilterClient { [weak self] success in
            guard success else {
                NSLog("XPCClient (opfilter): Failed to register as filter client")
                return
            }
            self?.fetchCurrentPolicy()
        }
    }

    private func fetchCurrentPolicy() {
        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({
            NSLog("XPCClient (opfilter): fetchCurrentPolicy error: %@", $0.localizedDescription)
        }) as? DaemonServiceProtocol else { return }

        proxy.fetchCurrentPolicy { [weak self] policyData in
            guard policyData.length > 0 else { return }
            guard let rules = try? JSONDecoder().decode([FAARule].self, from: policyData as Data) else {
                NSLog("XPCClient (opfilter): Failed to decode policy from daemon")
                return
            }
            self?.onPolicyUpdate?(rules)
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
}
