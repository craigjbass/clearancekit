//
//  EpochRatchetTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("EpochRatchet.verdict")
struct EpochRatchetVerdictTests {

    @Test("nil keychain epoch is treated as one-time forgiveness (verified)")
    func nilKeychainEpochIsVerified() {
        #expect(EpochRatchet.verdict(diskEpoch: 0, keychainEpoch: nil) == .verified)
        #expect(EpochRatchet.verdict(diskEpoch: 42, keychainEpoch: nil) == .verified)
    }

    @Test("equal epochs are verified")
    func equalEpochsVerified() {
        #expect(EpochRatchet.verdict(diskEpoch: 7, keychainEpoch: 7) == .verified)
    }

    @Test("disk epoch ahead of keychain is verified (post-crash, pre-keychain-sync)")
    func diskAheadVerified() {
        #expect(EpochRatchet.verdict(diskEpoch: 8, keychainEpoch: 7) == .verified)
    }

    @Test("keychain epoch strictly greater than disk is replay")
    func keychainAheadIsReplay() {
        #expect(EpochRatchet.verdict(diskEpoch: 5, keychainEpoch: 9) == .replay)
        #expect(EpochRatchet.verdict(diskEpoch: 0, keychainEpoch: 1) == .replay)
    }
}

@Suite("InMemoryEpochRatchetStore")
struct InMemoryEpochRatchetStoreTests {

    @Test("absent table returns nil")
    func absentTableReturnsNil() {
        let store = InMemoryEpochRatchetStore()
        #expect(store.epoch(forTable: "user_rules") == nil)
    }

    @Test("set then get round-trips per table")
    func setThenGetRoundTrips() {
        let store = InMemoryEpochRatchetStore()
        store.setEpoch(3, forTable: "user_rules")
        store.setEpoch(99, forTable: "feature_flags")
        #expect(store.epoch(forTable: "user_rules") == 3)
        #expect(store.epoch(forTable: "feature_flags") == 99)
    }

    @Test("set overwrites previous value")
    func setOverwrites() {
        let store = InMemoryEpochRatchetStore()
        store.setEpoch(1, forTable: "user_rules")
        store.setEpoch(2, forTable: "user_rules")
        #expect(store.epoch(forTable: "user_rules") == 2)
    }
}
