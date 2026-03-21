//
//  AllowlistStoreTests.swift
//  clearancekitTests
//

import Testing
import Foundation

// MARK: - AllowlistStoreTests

@Suite("AllowlistStore")
@MainActor
struct AllowlistStoreTests {

    private func makeEntry(signingID: String = "com.example.app") -> AllowlistEntry {
        AllowlistEntry(signingID: signingID)
    }

    private func makeAncestorEntry(signingID: String = "com.example.launcher") -> AncestorAllowlistEntry {
        AncestorAllowlistEntry(signingID: signingID)
    }

    // MARK: add

    @Test("add appends entry to userEntries and forwards to service")
    func addAppendsEntryAndForwardsToService() async throws {
        let service = FakePolicyService()
        let store = AllowlistStore(service: service, authenticate: approvedAuth)
        let entry = makeEntry()

        try await store.add(entry)

        #expect(store.userEntries.map(\.id) == [entry.id])
        #expect(service.addedEntries.map(\.id) == [entry.id])
    }

    @Test("add does nothing when authentication fails")
    func addDoesNothingOnAuthFailure() async {
        let service = FakePolicyService()
        let store = AllowlistStore(service: service, authenticate: failingAuth)

        do {
            try await store.add(makeEntry())
            Issue.record("Expected authentication error")
        } catch {}

        #expect(store.userEntries.isEmpty)
        #expect(service.addedEntries.isEmpty)
    }

    // MARK: remove

    @Test("remove deletes entry from userEntries and forwards ID to service")
    func removeDeletesEntryAndForwards() async throws {
        let service = FakePolicyService()
        let store = AllowlistStore(service: service, authenticate: approvedAuth)
        let entry = makeEntry()
        store.receivedUserEntries([entry])

        try await store.remove(entry)

        #expect(store.userEntries.isEmpty)
        #expect(service.removedEntryIDs == [entry.id])
    }

    @Test("remove does nothing when authentication fails")
    func removeDoesNothingOnAuthFailure() async {
        let service = FakePolicyService()
        let store = AllowlistStore(service: service, authenticate: failingAuth)
        let entry = makeEntry()
        store.receivedUserEntries([entry])

        do {
            try await store.remove(entry)
            Issue.record("Expected authentication error")
        } catch {}

        #expect(store.userEntries.count == 1)
        #expect(service.removedEntryIDs.isEmpty)
    }

    // MARK: addAncestor

    @Test("addAncestor appends ancestor entry to userAncestorEntries and forwards to service")
    func addAncestorAppendsAndForwards() async throws {
        let service = FakePolicyService()
        let store = AllowlistStore(service: service, authenticate: approvedAuth)
        let entry = makeAncestorEntry()

        try await store.addAncestor(entry)

        #expect(store.userAncestorEntries.map(\.id) == [entry.id])
        #expect(service.addedAncestorEntries.map(\.id) == [entry.id])
    }

    @Test("addAncestor does nothing when authentication fails")
    func addAncestorDoesNothingOnAuthFailure() async {
        let service = FakePolicyService()
        let store = AllowlistStore(service: service, authenticate: failingAuth)

        do {
            try await store.addAncestor(makeAncestorEntry())
            Issue.record("Expected authentication error")
        } catch {}

        #expect(store.userAncestorEntries.isEmpty)
        #expect(service.addedAncestorEntries.isEmpty)
    }

    // MARK: removeAncestor

    @Test("removeAncestor deletes ancestor entry from userAncestorEntries and forwards ID to service")
    func removeAncestorDeletesAndForwards() async throws {
        let service = FakePolicyService()
        let store = AllowlistStore(service: service, authenticate: approvedAuth)
        let entry = makeAncestorEntry()
        store.receivedUserAncestorEntries([entry])

        try await store.removeAncestor(entry)

        #expect(store.userAncestorEntries.isEmpty)
        #expect(service.removedAncestorEntryIDs == [entry.id])
    }

    // MARK: receivedManagedEntries / receivedUserEntries

    @Test("receivedManagedEntries updates managedEntries")
    func receivedManagedEntriesUpdates() {
        let service = FakePolicyService()
        let store = AllowlistStore(service: service, authenticate: approvedAuth)
        let entries = [makeEntry()]

        store.receivedManagedEntries(entries)

        #expect(store.managedEntries.map(\.id) == entries.map(\.id))
    }

    @Test("receivedUserEntries updates userEntries")
    func receivedUserEntriesUpdates() {
        let service = FakePolicyService()
        let store = AllowlistStore(service: service, authenticate: approvedAuth)
        let entries = [makeEntry()]

        store.receivedUserEntries(entries)

        #expect(store.userEntries.map(\.id) == entries.map(\.id))
    }

    @Test("receivedManagedAncestorEntries updates managedAncestorEntries")
    func receivedManagedAncestorEntriesUpdates() {
        let service = FakePolicyService()
        let store = AllowlistStore(service: service, authenticate: approvedAuth)
        let entries = [makeAncestorEntry()]

        store.receivedManagedAncestorEntries(entries)

        #expect(store.managedAncestorEntries.map(\.id) == entries.map(\.id))
    }

    @Test("receivedUserAncestorEntries updates userAncestorEntries")
    func receivedUserAncestorEntriesUpdates() {
        let service = FakePolicyService()
        let store = AllowlistStore(service: service, authenticate: approvedAuth)
        let entries = [makeAncestorEntry()]

        store.receivedUserAncestorEntries(entries)

        #expect(store.userAncestorEntries.map(\.id) == entries.map(\.id))
    }
}
