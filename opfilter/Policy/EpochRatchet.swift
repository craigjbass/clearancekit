//
//  EpochRatchet.swift
//  opfilter
//
//  Replay-attack mitigation for the on-disk signed policy database.
//
//  Each signed table carries a monotonically-increasing epoch in its signed
//  payload. After every successful save, the latest epoch is also persisted
//  in the System Keychain under the same opfilter-only ACL used by
//  PolicySigner. On load, the disk epoch is compared against the keychain
//  epoch: a strictly-lower disk epoch indicates the table has been replaced
//  by an older legitimately-signed snapshot (replay) and is treated as
//  suspect.
//

import Foundation
import Security

protocol EpochRatchetStore: Sendable {
    func epoch(forTable table: String) -> UInt64?
    func setEpoch(_ epoch: UInt64, forTable table: String)
}

enum RatchetVerdict: Equatable {
    case verified
    case replay
}

enum EpochRatchet {
    /// Replaceable for tests. Production code uses the System-Keychain-backed store.
    nonisolated(unsafe) static var store: EpochRatchetStore = SystemKeychainEpochRatchetStore()

    static func epoch(forTable table: String) -> UInt64? {
        store.epoch(forTable: table)
    }

    static func setEpoch(_ epoch: UInt64, forTable table: String) {
        store.setEpoch(epoch, forTable: table)
    }

    /// Pure decision function. A missing keychain epoch is treated as a one-time
    /// forgiveness case (fresh install, keychain wipe) — we do not have a
    /// trustworthy lower bound to enforce, so the verdict is `.verified` and the
    /// next save re-seeds the keychain.
    static func verdict(diskEpoch: UInt64, keychainEpoch: UInt64?) -> RatchetVerdict {
        guard let keychainEpoch else { return .verified }
        return keychainEpoch > diskEpoch ? .replay : .verified
    }
}

struct InMemoryEpochRatchetStore: EpochRatchetStore {
    private final class Storage: @unchecked Sendable {
        var values: [String: UInt64] = [:]
        let lock = NSLock()
    }
    private let storage = Storage()

    init() {}

    func epoch(forTable table: String) -> UInt64? {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        return storage.values[table]
    }

    func setEpoch(_ epoch: UInt64, forTable table: String) {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        storage.values[table] = epoch
    }
}

struct SystemKeychainEpochRatchetStore: EpochRatchetStore {
    private static let service = "uk.craigbass.clearancekit.epoch-ratchet"

    private static let systemKeychain: SecKeychain? = {
        var kc: SecKeychain?
        // SecKeychainOpen is deprecated (macOS 10.10) but remains the only API
        // that accepts an explicit keychain path; matches PolicySigner.
        let status = SecKeychainOpen("/Library/Keychains/System.keychain", &kc)
        if status != errSecSuccess {
            NSLog("EpochRatchet: Could not open System Keychain (%d)", status)
        }
        return kc
    }()

    init() {}

    func epoch(forTable table: String) -> UInt64? {
        var query: [CFString: Any] = [
            kSecClass:          kSecClassGenericPassword,
            kSecAttrService:    Self.service,
            kSecAttrAccount:    table,
            kSecReturnData:     true,
        ]
        if let kc = Self.systemKeychain { query[kSecUseKeychain] = kc; query[kSecMatchSearchList] = [kc] as CFArray }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data, data.count == MemoryLayout<UInt64>.size else {
            return nil
        }
        return data.withUnsafeBytes { raw -> UInt64 in
            UInt64(bigEndian: raw.load(as: UInt64.self))
        }
    }

    func setEpoch(_ epoch: UInt64, forTable table: String) {
        var bigEndian = epoch.bigEndian
        let data = Data(bytes: &bigEndian, count: MemoryLayout<UInt64>.size)

        var matchQuery: [CFString: Any] = [
            kSecClass:          kSecClassGenericPassword,
            kSecAttrService:    Self.service,
            kSecAttrAccount:    table,
        ]
        if let kc = Self.systemKeychain { matchQuery[kSecMatchSearchList] = [kc] as CFArray }

        let update: [CFString: Any] = [
            kSecValueData: data,
        ]
        let updateStatus = SecItemUpdate(matchQuery as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess { return }

        guard updateStatus == errSecItemNotFound else {
            NSLog("EpochRatchet: SecItemUpdate failed for %@ (%d)", table, updateStatus)
            return
        }

        guard let access = Self.makeDaemonOnlyAccess() else { return }

        var addQuery: [CFString: Any] = [
            kSecClass:          kSecClassGenericPassword,
            kSecAttrService:    Self.service,
            kSecAttrAccount:    table,
            kSecValueData:      data,
            kSecAttrAccess:     access,
        ]
        if let kc = Self.systemKeychain { addQuery[kSecUseKeychain] = kc }

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus != errSecSuccess {
            NSLog("EpochRatchet: SecItemAdd failed for %@ (%d)", table, addStatus)
        }
    }

    private static func makeDaemonOnlyAccess() -> SecAccess? {
        var trustedApp: SecTrustedApplication?
        let appStatus = SecTrustedApplicationCreateFromPath(nil, &trustedApp)
        guard appStatus == errSecSuccess, let app = trustedApp else {
            NSLog("EpochRatchet: SecTrustedApplicationCreateFromPath failed (%d)", appStatus)
            return nil
        }
        var access: SecAccess?
        let accessStatus = SecAccessCreate(service as CFString, [app] as CFArray, &access)
        guard accessStatus == errSecSuccess, let result = access else {
            NSLog("EpochRatchet: SecAccessCreate failed (%d)", accessStatus)
            return nil
        }
        return result
    }
}
