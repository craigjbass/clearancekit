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

// nonisolated(unsafe): prevents @MainActor inference on this file-scope constant.
// Logger is Sendable and immutable so this is safe.
private nonisolated(unsafe) let logger = Logger(subsystem: "uk.craigbass.clearancekit", category: "system-extension")

@MainActor
final class SystemExtensionManager: NSObject, ObservableObject {
    static let shared = SystemExtensionManager()

    @Published private(set) var extensionStatus: ExtensionStatus = .unknown
    @Published private(set) var statusMessage: String = "Unknown"

    enum ExtensionStatus {
        case unknown
        case notInstalled
        case activating
        case activated
        case failed
    }

    private static let extensionBundleIdentifier = "uk.craigbass.clearancekit.opfilter"

    private override init() {
        super.init()
    }

    func activateExtension() {
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
        extensionStatus = .activating
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
                self.extensionStatus = .activated
                self.statusMessage = "Extension activated"
            case .willCompleteAfterReboot:
                self.extensionStatus = .activating
                self.statusMessage = "Reboot required to complete"
            @unknown default:
                self.extensionStatus = .unknown
                self.statusMessage = "Unknown result"
            }
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
