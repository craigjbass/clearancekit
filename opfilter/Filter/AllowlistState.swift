//
//  AllowlistState.swift
//  opfilter
//

import Foundation
import os

final class AllowlistState: @unchecked Sendable {
    private let allowlistStorage: OSAllocatedUnfairLock<[AllowlistEntry]>
    private let ancestorAllowlistStorage: OSAllocatedUnfairLock<[AncestorAllowlistEntry]>

    init(
        initialAllowlist: [AllowlistEntry] = baselineAllowlist,
        initialAncestorAllowlist: [AncestorAllowlistEntry] = []
    ) {
        self.allowlistStorage = OSAllocatedUnfairLock(initialState: initialAllowlist)
        self.ancestorAllowlistStorage = OSAllocatedUnfairLock(initialState: initialAncestorAllowlist)
    }

    func currentAllowlist() -> [AllowlistEntry] {
        allowlistStorage.withLock { $0 }
    }

    func currentAncestorAllowlist() -> [AncestorAllowlistEntry] {
        ancestorAllowlistStorage.withLock { $0 }
    }

    func updateAllowlist(_ entries: [AllowlistEntry]) {
        allowlistStorage.withLock { $0 = entries }
    }

    func updateAncestorAllowlist(_ entries: [AncestorAllowlistEntry]) {
        ancestorAllowlistStorage.withLock { $0 = entries }
    }
}
