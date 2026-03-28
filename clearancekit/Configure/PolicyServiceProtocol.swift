//
//  PolicyServiceProtocol.swift
//  clearancekit
//

import Foundation

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
    func setJailEnabled(_ enabled: Bool)
}

typealias Authenticate = @Sendable (String) async throws -> Void
