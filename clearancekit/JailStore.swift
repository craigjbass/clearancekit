//
//  JailStore.swift
//  clearancekit
//

import Foundation
import Combine

@MainActor
final class JailStore: ObservableObject {
    static let shared = JailStore(
        service: XPCClient.shared,
        authenticate: { try await BiometricAuth.authenticate(reason: $0) }
    )

    @Published private(set) var userRules: [JailRule] = []

    private let service: PolicyServiceProtocol
    private let authenticate: Authenticate

    init(service: PolicyServiceProtocol, authenticate: @escaping Authenticate) {
        self.service = service
        self.authenticate = authenticate
    }

    // MARK: - Service push

    func receivedUserRules(_ rules: [JailRule]) {
        userRules = rules
    }

    // MARK: - Mutations

    func add(_ rule: JailRule) async throws {
        try await authenticate("Add a jail rule")
        userRules.append(rule)
        service.addJailRule(rule)
    }

    func update(_ rule: JailRule) async throws {
        try await authenticate("Update a jail rule")
        if let index = userRules.firstIndex(where: { $0.id == rule.id }) {
            userRules[index] = rule
        }
        service.updateJailRule(rule)
    }

    func remove(_ rule: JailRule) async throws {
        try await authenticate("Remove a jail rule")
        userRules.removeAll { $0.id == rule.id }
        service.removeJailRule(ruleID: rule.id)
    }

    func allowPath(_ path: String, inRule ruleID: UUID) async throws {
        guard let index = userRules.firstIndex(where: { $0.id == ruleID }) else { return }
        try await authenticate("Allow this path in jail rule")
        guard !userRules[index].allowedPathPrefixes.contains(path) else { return }
        userRules[index].allowedPathPrefixes.append(path)
        service.updateJailRule(userRules[index])
    }
}
