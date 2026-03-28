//
//  PolicyStore.swift
//  clearancekit
//

import Foundation
import Combine

/// View-layer cache of the active policy.
///
/// The opfilter service (running as root) is the authoritative store. This class
/// holds a local copy pushed down via XPC and forwards all mutations up to opfilter.
/// There is no local disk I/O — opfilter owns persistence.
@MainActor
final class PolicyStore: ObservableObject {
    static let shared = PolicyStore(
        service: XPCClient.shared,
        authenticate: { try await BiometricAuth.authenticate(reason: $0) }
    )

    /// Compile-time baseline rules. These are enforced by opfilter first and
    /// cannot be modified through the GUI.
    @Published private(set) var baselineRules: [FAARule] = faaPolicy

    /// Rules delivered via MDM or a .mobileconfig profile. Read-only in the GUI;
    /// the authoritative snapshot is pushed by opfilter via `receivedManagedRules(_:)`.
    @Published private(set) var managedRules: [FAARule] = []

    /// User-configurable rules managed by opfilter. Mutations are sent over XPC;
    /// the authoritative snapshot is pushed back via `receivedUserRules(_:)`.
    @Published private(set) var userRules: [FAARule] = []

    private let service: PolicyServiceProtocol
    private let authenticate: Authenticate

    init(service: PolicyServiceProtocol, authenticate: @escaping Authenticate) {
        self.service = service
        self.authenticate = authenticate
    }

    // MARK: - Service push

    func receivedManagedRules(_ rules: [FAARule]) {
        managedRules = rules
    }

    func receivedUserRules(_ rules: [FAARule]) {
        userRules = rules
    }

    // MARK: - Mutations (Touch ID required, then optimistic local update + XPC)

    func add(_ rule: FAARule) async throws {
        try await authenticate("Add a policy rule")
        userRules.append(rule)
        service.addRule(rule)
    }

    func update(_ rule: FAARule) async throws {
        guard let index = userRules.firstIndex(where: { $0.id == rule.id }) else { return }
        try await authenticate("Update a policy rule")
        userRules[index] = rule
        service.updateRule(rule)
    }

    func remove(_ rule: FAARule) async throws {
        try await authenticate("Remove a policy rule")
        userRules.removeAll { $0.id == rule.id }
        service.removeRule(ruleID: rule.id)
    }

    func allowProcess(teamID: String, signingID: String, inRule ruleID: UUID) async throws {
        guard userRules.contains(where: { $0.id == ruleID }) else { return }
        try await authenticate("Allow this process")
        let signature = normalisedSignature(teamID: teamID, signingID: signingID)
        guard let updated = appendSignature(signature, toRuleWithID: ruleID, keyPath: \.allowedSignatures) else { return }
        service.updateRule(updated)
    }

    // MARK: - Batch mutations (single Touch ID prompt for multiple rules)

    func addAll(_ rules: [FAARule], reason: String) async throws {
        let newRules = rules.filter { rule in !userRules.contains { $0.id == rule.id } }
        guard !newRules.isEmpty else { return }
        try await authenticate(reason)
        for rule in newRules {
            userRules.append(rule)
            service.addRule(rule)
        }
    }

    func removeAll(_ rules: [FAARule], reason: String) async throws {
        let ids = Set(rules.map(\.id))
        guard userRules.contains(where: { ids.contains($0.id) }) else { return }
        try await authenticate(reason)
        userRules.removeAll { ids.contains($0.id) }
        for rule in rules {
            service.removeRule(ruleID: rule.id)
        }
    }

    func updateAll(_ rules: [FAARule], reason: String) async throws {
        let updates = rules.filter { rule in userRules.contains { $0.id == rule.id } }
        guard !updates.isEmpty else { return }
        try await authenticate(reason)
        for rule in updates {
            guard let index = userRules.firstIndex(where: { $0.id == rule.id }) else { continue }
            userRules[index] = rule
            service.updateRule(rule)
        }
    }

    func replaceAll(_ oldRules: [FAARule], with newRules: [FAARule], reason: String) async throws {
        try await authenticate(reason)
        let oldIDs = Set(oldRules.map(\.id))
        userRules.removeAll { oldIDs.contains($0.id) }
        for rule in oldRules { service.removeRule(ruleID: rule.id) }
        for rule in newRules {
            userRules.append(rule)
            service.addRule(rule)
        }
    }

    func allowAncestor(teamID: String, signingID: String, inRule ruleID: UUID) async throws {
        guard userRules.contains(where: { $0.id == ruleID }) else { return }
        try await authenticate("Allow this ancestor process")
        let signature = normalisedSignature(teamID: teamID, signingID: signingID)
        guard let updated = appendSignature(signature, toRuleWithID: ruleID, keyPath: \.allowedAncestorSignatures) else { return }
        service.updateRule(updated)
    }

    // MARK: - Private helpers

    private func normalisedSignature(teamID: String, signingID: String) -> ProcessSignature {
        ProcessSignature(
            teamID: teamID.isEmpty ? appleTeamID : teamID,
            signingID: signingID.isEmpty ? "*" : signingID
        )
    }

    private func appendSignature(
        _ signature: ProcessSignature,
        toRuleWithID ruleID: UUID,
        keyPath: WritableKeyPath<FAARule, [ProcessSignature]>
    ) -> FAARule? {
        guard let index = userRules.firstIndex(where: { $0.id == ruleID }) else { return nil }
        var rule = userRules[index]
        if !rule[keyPath: keyPath].contains(signature) {
            rule[keyPath: keyPath].append(signature)
        }
        userRules[index] = rule
        return rule
    }
}
