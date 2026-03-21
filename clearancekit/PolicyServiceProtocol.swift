//
//  PolicyServiceProtocol.swift
//  clearancekit
//

import Foundation

/// The subset of the XPC service interface that PolicyStore and AllowlistStore
/// need to forward mutations to opfilter. Scoped to the main actor so callers
/// on the main actor can invoke methods synchronously.
@MainActor
protocol PolicyServiceProtocol: AnyObject {
    func addRule(_ rule: FAARule)
    func updateRule(_ rule: FAARule)
    func removeRule(ruleID: UUID)
    func addAllowlistEntry(_ entry: AllowlistEntry)
    func removeAllowlistEntry(entryID: UUID)
    func addAncestorAllowlistEntry(_ entry: AncestorAllowlistEntry)
    func removeAncestorAllowlistEntry(entryID: UUID)
    func addJailRule(_ rule: JailRule)
    func updateJailRule(_ rule: JailRule)
    func removeJailRule(ruleID: UUID)
}

/// A function that authenticates the user before a sensitive mutation is applied.
/// The `reason` string is shown in the Touch ID / password prompt.
typealias Authenticate = @Sendable (String) async throws -> Void
