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
    static let shared = AllowlistStore()

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

    private init() {}

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
        try await BiometricAuth.authenticate(reason: "Add a global allowlist entry")
        userEntries.append(entry)
        XPCClient.shared.addAllowlistEntry(entry)
    }

    func remove(_ entry: AllowlistEntry) async throws {
        try await BiometricAuth.authenticate(reason: "Remove a global allowlist entry")
        userEntries.removeAll { $0.id == entry.id }
        XPCClient.shared.removeAllowlistEntry(entryID: entry.id)
    }

    func addAncestor(_ entry: AncestorAllowlistEntry) async throws {
        try await BiometricAuth.authenticate(reason: "Add a global ancestor allowlist entry")
        userAncestorEntries.append(entry)
        XPCClient.shared.addAncestorAllowlistEntry(entry)
    }

    func removeAncestor(_ entry: AncestorAllowlistEntry) async throws {
        try await BiometricAuth.authenticate(reason: "Remove a global ancestor allowlist entry")
        userAncestorEntries.removeAll { $0.id == entry.id }
        XPCClient.shared.removeAncestorAllowlistEntry(entryID: entry.id)
    }
}
