//
//  BundleUpdaterStore.swift
//  clearancekit
//

import Foundation
import Combine

@MainActor
final class BundleUpdaterStore: ObservableObject {
    static let shared = BundleUpdaterStore(
        service: XPCClient.shared,
        authenticate: { try await BiometricAuth.authenticate(reason: $0) }
    )

    @Published private(set) var signatures: [BundleUpdaterSignature] = []

    private let service: PolicyServiceProtocol
    private let authenticate: Authenticate

    init(service: PolicyServiceProtocol, authenticate: @escaping Authenticate) {
        self.service = service
        self.authenticate = authenticate
    }

    func receivedSignatures(_ signatures: [BundleUpdaterSignature]) {
        self.signatures = signatures
    }

    func add(_ signature: BundleUpdaterSignature) async throws {
        try await authenticate("Add a bundle updater allowlist entry")
        signatures.append(signature)
        service.saveBundleUpdaterSignatures(signatures)
    }

    func remove(_ signature: BundleUpdaterSignature) async throws {
        try await authenticate("Remove a bundle updater allowlist entry")
        signatures.removeAll { $0.id == signature.id }
        service.saveBundleUpdaterSignatures(signatures)
    }
}
