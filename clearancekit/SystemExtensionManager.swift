//
//  SystemExtensionManager.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import AppKit
import Foundation
import Combine
import os
@preconcurrency import SystemExtensions

private let logger = Logger(subsystem: "uk.craigbass.clearancekit", category: "system-extension")

@MainActor
final class SystemExtensionManager: NSObject, ObservableObject {
    static let shared = SystemExtensionManager()

    @Published private(set) var extensionStatus: ExtensionStatus = .unknown
    @Published private(set) var statusMessage: String = "Unknown"

    enum ExtensionStatus {
        case unknown
        case notInstalled
        case activating
        case deactivating
        case activated
        case failed
    }

    private enum PendingAction {
        case activating
        case deactivating
    }

    private static let extensionBundleIdentifier = "uk.craigbass.clearancekit.opfilter"

    private var pendingAction: PendingAction?
    private var isReplacing = false

    private override init() {
        super.init()
    }

    func replaceExtension() {
        isReplacing = true
        pendingAction = .deactivating
        extensionStatus = .deactivating
        statusMessage = "Updating..."

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionBundleIdentifier,
            queue: .main
        )
        request.delegate = self
        DispatchQueue.global(qos: .userInitiated).async {
            OSSystemExtensionManager.shared.submitRequest(request)
        }
        logger.info("SystemExtensionManager: Submitted deactivation request for replacement")
    }

    func activateExtension() {
        pendingAction = .activating
        extensionStatus = .activating
        statusMessage = "Requesting activation..."

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionBundleIdentifier,
            queue: .main
        )
        request.delegate = self
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.global(qos: .userInitiated).async {
            OSSystemExtensionManager.shared.submitRequest(request)
        }
        logger.info("SystemExtensionManager: Submitted activation request for \(Self.extensionBundleIdentifier, privacy: .public)")
    }

    func deactivateExtension() {
        pendingAction = .deactivating
        extensionStatus = .deactivating
        statusMessage = "Requesting deactivation..."

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionBundleIdentifier,
            queue: .main
        )
        request.delegate = self
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.global(qos: .userInitiated).async {
            OSSystemExtensionManager.shared.submitRequest(request)
        }
        logger.info("SystemExtensionManager: Submitted deactivation request for \(Self.extensionBundleIdentifier, privacy: .public)")
    }
}

extension SystemExtensionManager: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        logger.info("SystemExtensionManager: Replacing extension \(existing.bundleVersion, privacy: .public) with \(ext.bundleVersion, privacy: .public)")
        return .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        logger.info("SystemExtensionManager: User approval required - check System Settings > Privacy & Security")
        Task { @MainActor in
            self.statusMessage = "Approval required - check System Settings"
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        logger.info("SystemExtensionManager: Request finished with result: \(result.rawValue)")
        Task { @MainActor in
            switch result {
            case .completed:
                switch self.pendingAction {
                case .deactivating:
                    if self.isReplacing {
                        self.isReplacing = false
                        self.activateExtension()
                        return
                    }
                    self.extensionStatus = .notInstalled
                    self.statusMessage = "Extension deactivated"
                case .activating:
                    self.extensionStatus = .activated
                    self.statusMessage = "Extension activated"
                    XPCClient.shared.reconnectAfterExtensionActivation()
                case nil:
                    logger.error("SystemExtensionManager: didFinishWithResult called with no pending action")
                    self.extensionStatus = .unknown
                    self.statusMessage = "Unknown result"
                }
            case .willCompleteAfterReboot:
                self.extensionStatus = .activating
                self.statusMessage = "Reboot required to complete"
            @unknown default:
                self.extensionStatus = .unknown
                self.statusMessage = "Unknown result"
            }
            self.pendingAction = nil
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        logger.error("SystemExtensionManager: Request failed with error: \(error.localizedDescription, privacy: .public)")
        Task { @MainActor in
            self.extensionStatus = .failed
            self.statusMessage = "Failed: \(error.localizedDescription)"
        }
    }
}
