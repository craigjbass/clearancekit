//
//  XPCClient.swift
//  opfilter
//
//  Created by Craig J. Bass on 19/02/2026.
//

import Foundation

final class XPCClient: NSObject {
    static let shared = XPCClient()

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

        conn.invalidationHandler = {
            NSLog("XPCClient (opfilter): Connection to daemon invalidated")
        }
        conn.interruptionHandler = {
            NSLog("XPCClient (opfilter): Connection to daemon interrupted")
        }

        conn.resume()
        connection = conn
        NSLog("XPCClient (opfilter): Connected to daemon at %@", XPCConstants.daemonServiceName)
    }

    func reportEvent(_ event: FolderOpenEvent) {
        guard let proxy = connection?.remoteObjectProxy as? DaemonServiceProtocol else { return }
        proxy.reportEvent(event)
    }

    func reportMonitoringStatus(_ isActive: Bool) {
        guard let proxy = connection?.remoteObjectProxy as? DaemonServiceProtocol else { return }
        proxy.reportMonitoringStatus(isActive)
    }
}
