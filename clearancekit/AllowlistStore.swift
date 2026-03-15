//
//  AllowlistStore.swift
//  clearancekit
//

import Foundation
import Combine

/// View-layer cache of the active global allowlist.
///
/// The daemon is the authoritative store. This class holds a local copy
/// pushed down via XPC and forwards all mutations up to the daemon.
@MainActor
final class AllowlistStore: ObservableObject {
    static let shared = AllowlistStore()

    /// Baseline entries: compiled-in signing-ID rules plus XProtect executables
    /// discovered by scanning the bundle at launch. Always allowed; read-only in the GUI.
    @Published private(set) var baselineEntries: [AllowlistEntry] = baselineAllowlist + enumerateXProtectEntries()

    /// Entries delivered via MDM or a .mobileconfig profile. Read-only in the GUI.
    @Published private(set) var managedEntries: [AllowlistEntry] = []

    /// User-configurable entries managed by the daemon.
    @Published private(set) var userEntries: [AllowlistEntry] = []

    private init() {}

    // MARK: - Daemon push

    func receivedManagedEntries(_ entries: [AllowlistEntry]) {
        managedEntries = entries
    }

    func receivedUserEntries(_ entries: [AllowlistEntry]) {
        userEntries = entries
    }

    // MARK: - Mutations

    func add(_ entry: AllowlistEntry) async throws {
        try await BiometricAuth.authenticate(reason: "Add a global allowlist entry")
        userEntries.append(entry)
        XPCClient.shared.addAllowlistEntry(entry)
    }

    func remove(_ entry: AllowlistEntry) async throws {
        try await BiometricAuth.authenticate(reason: "Remove a global allowlist entry")
        userEntries.removeAll { $0.id == entry.id }
        XPCClient.shared.removeAllowlistEntry(entryID: entry.id)
    }
}
