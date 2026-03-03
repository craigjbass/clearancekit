//
//  SystemExtensionManager.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import AppKit
import Foundation
import Combine
@preconcurrency import SystemExtensions

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
        NSLog("SystemExtensionManager: Submitted activation request for %@", Self.extensionBundleIdentifier)
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
        NSLog("SystemExtensionManager: Submitted deactivation request for %@", Self.extensionBundleIdentifier)
    }
}

extension SystemExtensionManager: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        NSLog("SystemExtensionManager: Replacing extension %@ with %@", existing.bundleVersion, ext.bundleVersion)
        return .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        NSLog("SystemExtensionManager: User approval required - check System Settings > Privacy & Security")
        Task { @MainActor in
            self.statusMessage = "Approval required - check System Settings"
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        NSLog("SystemExtensionManager: Request finished with result: %d", result.rawValue)
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
        NSLog("SystemExtensionManager: Request failed with error: %@", error.localizedDescription)
        Task { @MainActor in
            self.extensionStatus = .failed
            self.statusMessage = "Failed: \(error.localizedDescription)"
        }
    }
}
