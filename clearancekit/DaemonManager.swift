//
//  DaemonManager.swift
//  clearancekit
//
//  Created by Craig J. Bass on 19/02/2026.
//

import AppKit
import Foundation
import Combine
@preconcurrency import ServiceManagement

@MainActor
final class DaemonManager: NSObject, ObservableObject {
    static let shared = DaemonManager()

    @Published private(set) var status: DaemonStatus = .unknown
    @Published private(set) var statusMessage: String = "Checking..."

    enum DaemonStatus {
        case unknown
        case notRegistered
        case requiresApproval
        case enabled
        case failed
    }

    private let service = SMAppService.daemon(plistName: "uk.craigbass.clearancekit.daemon.plist")

    private override init() {
        super.init()
        refreshStatus()
    }

    func refreshStatus() {
        updateFromServiceStatus()
    }

    func registerDaemon() {
        Task {
            let svc = service
            NSApp.setActivationPolicy(.regular)
            NSApp.activate(ignoringOtherApps: true)
            do {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    DispatchQueue.global(qos: .userInitiated).async {
                        do {
                            try svc.register()
                            continuation.resume()
                        } catch {
                            continuation.resume(throwing: error)
                        }
                    }
                }
                NSApp.setActivationPolicy(.accessory)
                updateFromServiceStatus()
                NSLog("DaemonManager: Registered successfully, status: %d", service.status.rawValue)
            } catch {
                status = .failed
                statusMessage = "Failed: \(error.localizedDescription)"
                NSLog("DaemonManager: Registration failed: %@", error.localizedDescription)
            }
        }
    }

    func unregisterDaemon() {
        Task {
            do {
                try await service.unregister()
                updateFromServiceStatus()
                NSLog("DaemonManager: Unregistered successfully")
            } catch {
                status = .failed
                statusMessage = "Failed to unregister: \(error.localizedDescription)"
                NSLog("DaemonManager: Unregistration failed: %@", error.localizedDescription)
            }
        }
    }

    func openSystemSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    private func updateFromServiceStatus() {
        switch service.status {
        case .notRegistered:
            status = .notRegistered
            statusMessage = "Not registered"
        case .enabled:
            status = .enabled
            statusMessage = "Running"
        case .requiresApproval:
            status = .requiresApproval
            statusMessage = "Awaiting approval"
        case .notFound:
            status = .unknown
            statusMessage = "Not found in bundle"
        @unknown default:
            status = .unknown
            statusMessage = "Unknown"
        }
    }
}
