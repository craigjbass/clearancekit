//
//  AllowlistStore.swift
//  clearancekit
//

import Foundation
import Combine

/// View-layer cache of the active global allowlist.
///
/// The opfilter service is the authoritative store. This class holds a local copy
/// pushed down via XPC and forwards all mutations up to opfilter.
@MainActor
final class AllowlistStore: ObservableObject {
    static let shared = AllowlistStore(
        service: XPCClient.shared,
        authenticate: { try await BiometricAuth.authenticate(reason: $0) }
    )

    /// Baseline entries: compiled-in signing-ID rules plus XProtect executables
    /// discovered by scanning the bundle at launch. Always allowed; read-only in the GUI.
    @Published private(set) var baselineEntries: [AllowlistEntry] = baselineAllowlist + enumerateXProtectEntries()

    /// Entries delivered via MDM or a .mobileconfig profile. Read-only in the GUI.
    @Published private(set) var managedEntries: [AllowlistEntry] = []

    /// User-configurable entries managed by opfilter.
    @Published private(set) var userEntries: [AllowlistEntry] = []

    /// Ancestor allowlist entries delivered via MDM or a .mobileconfig profile. Read-only in the GUI.
    @Published private(set) var managedAncestorEntries: [AncestorAllowlistEntry] = []

    /// User-configurable ancestor allowlist entries managed by opfilter.
    @Published private(set) var userAncestorEntries: [AncestorAllowlistEntry] = []

    private let service: PolicyServiceProtocol
    private let authenticate: Authenticate

    init(service: PolicyServiceProtocol, authenticate: @escaping Authenticate) {
        self.service = service
        self.authenticate = authenticate
    }

    // MARK: - Service push

    func receivedManagedEntries(_ entries: [AllowlistEntry]) {
        managedEntries = entries
    }

    func receivedUserEntries(_ entries: [AllowlistEntry]) {
        userEntries = entries
    }

    func receivedManagedAncestorEntries(_ entries: [AncestorAllowlistEntry]) {
        managedAncestorEntries = entries
    }

    func receivedUserAncestorEntries(_ entries: [AncestorAllowlistEntry]) {
        userAncestorEntries = entries
    }

    // MARK: - Mutations

    func add(_ entry: AllowlistEntry) async throws {
        try await authenticate("Add a global allowlist entry")
        userEntries.append(entry)
        service.addAllowlistEntry(entry)
    }

    func remove(_ entry: AllowlistEntry) async throws {
        try await authenticate("Remove a global allowlist entry")
        userEntries.removeAll { $0.id == entry.id }
        service.removeAllowlistEntry(entryID: entry.id)
    }

    func update(_ entry: AllowlistEntry) async throws {
        try await authenticate("Update a global allowlist entry")
        userEntries.removeAll { $0.id == entry.id }
        userEntries.append(entry)
        service.removeAllowlistEntry(entryID: entry.id)
        service.addAllowlistEntry(entry)
    }

    func addAncestor(_ entry: AncestorAllowlistEntry) async throws {
        try await authenticate("Add a global ancestor allowlist entry")
        userAncestorEntries.append(entry)
        service.addAncestorAllowlistEntry(entry)
    }

    func removeAncestor(_ entry: AncestorAllowlistEntry) async throws {
        try await authenticate("Remove a global ancestor allowlist entry")
        userAncestorEntries.removeAll { $0.id == entry.id }
        service.removeAncestorAllowlistEntry(entryID: entry.id)
    }

    func updateAncestor(_ entry: AncestorAllowlistEntry) async throws {
        try await authenticate("Update a global ancestor allowlist entry")
        userAncestorEntries.removeAll { $0.id == entry.id }
        userAncestorEntries.append(entry)
        service.removeAncestorAllowlistEntry(entryID: entry.id)
        service.addAncestorAllowlistEntry(entry)
    }
}
