//
//  QuietListStore.swift
//  clearancekit
//

import Foundation
import Combine

@MainActor
final class QuietListStore: ObservableObject {
    static let shared = QuietListStore(
        service: XPCClient.shared,
        authenticate: { try await BiometricAuth.authenticate(reason: $0) }
    )

    let baselineEntries: [QuietListEntry] = baselineQuietList
    @Published private(set) var managedEntries: [QuietListEntry] = []
    @Published private(set) var userEntries: [QuietListEntry] = []

    private let service: PolicyServiceProtocol
    private let authenticate: Authenticate

    init(service: PolicyServiceProtocol, authenticate: @escaping Authenticate) {
        self.service = service
        self.authenticate = authenticate
    }

    // MARK: - Service push

    func receivedManagedEntries(_ entries: [QuietListEntry]) {
        managedEntries = entries
    }

    func receivedUserEntries(_ entries: [QuietListEntry]) {
        userEntries = entries
    }

    // MARK: - Mutations

    func add(_ entry: QuietListEntry) async throws {
        try await authenticate("Add a quiet list entry")
        userEntries.append(entry)
        service.addQuietListEntry(entry)
    }

    func remove(_ entry: QuietListEntry) async throws {
        try await authenticate("Remove a quiet list entry")
        userEntries.removeAll { $0.id == entry.id }
        service.removeQuietListEntry(entryID: entry.id)
    }
}
