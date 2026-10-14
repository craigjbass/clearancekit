//
//  QuietListStoreTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("QuietListStore")
@MainActor
struct QuietListStoreTests {

    private func makeEntry(signingID: String = "com.example.noisy") -> QuietListEntry {
        QuietListEntry(id: UUID(), signingID: signingID, processPath: "", platformBinary: false, teamID: "TEAM123")
    }

    @Test("baselineEntries is the compiled-in baseline quiet list")
    func baselineEntriesIsBaseline() {
        let store = QuietListStore(service: FakePolicyService(), authenticate: approvedAuth)

        #expect(store.baselineEntries == baselineQuietList)
    }

    @Test("add appends entry to userEntries and forwards to service")
    func addAppendsAndForwards() async throws {
        let service = FakePolicyService()
        let store = QuietListStore(service: service, authenticate: approvedAuth)
        let entry = makeEntry()

        try await store.add(entry)

        #expect(store.userEntries == [entry])
        #expect(service.addedQuietListEntries == [entry])
    }

    @Test("add does nothing when authentication fails")
    func addDoesNothingOnAuthFailure() async {
        let service = FakePolicyService()
        let store = QuietListStore(service: service, authenticate: failingAuth)

        do {
            try await store.add(makeEntry())
            Issue.record("Expected authentication error")
        } catch is AuthError {}
        catch {
            Issue.record("Unexpected error \(error)")
        }

        #expect(store.userEntries.isEmpty)
        #expect(service.addedQuietListEntries.isEmpty)
    }

    @Test("remove deletes entry from userEntries and forwards ID to service")
    func removeDeletesAndForwards() async throws {
        let service = FakePolicyService()
        let store = QuietListStore(service: service, authenticate: approvedAuth)
        let entry = makeEntry()
        store.receivedUserEntries([entry])

        try await store.remove(entry)

        #expect(store.userEntries.isEmpty)
        #expect(service.removedQuietListEntryIDs == [entry.id])
    }

    @Test("remove does nothing when authentication fails")
    func removeDoesNothingOnAuthFailure() async {
        let service = FakePolicyService()
        let store = QuietListStore(service: service, authenticate: failingAuth)
        let entry = makeEntry()
        store.receivedUserEntries([entry])

        do {
            try await store.remove(entry)
            Issue.record("Expected authentication error")
        } catch is AuthError {}
        catch {
            Issue.record("Unexpected error \(error)")
        }

        #expect(store.userEntries == [entry])
        #expect(service.removedQuietListEntryIDs.isEmpty)
    }

    @Test("receivedManagedEntries replaces managedEntries")
    func receivedManagedEntriesReplaces() {
        let store = QuietListStore(service: FakePolicyService(), authenticate: approvedAuth)
        let entries = [makeEntry(signingID: "managed.noisy")]

        store.receivedManagedEntries(entries)

        #expect(store.managedEntries == entries)
    }

    @Test("receivedUserEntries replaces userEntries")
    func receivedUserEntriesReplaces() {
        let store = QuietListStore(service: FakePolicyService(), authenticate: approvedAuth)
        let entries = [makeEntry(signingID: "user.noisy")]

        store.receivedUserEntries(entries)

        #expect(store.userEntries == entries)
    }
}
