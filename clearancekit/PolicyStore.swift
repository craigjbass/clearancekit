//
//  PolicyStore.swift
//  clearancekit
//

import Foundation
import Combine

/// View-layer cache of the active policy.
///
/// The daemon (running as root) is the authoritative store. This class holds a
/// local copy pushed down via XPC and forwards all mutations up to the daemon.
/// There is no local disk I/O — the daemon owns persistence.
@MainActor
final class PolicyStore: ObservableObject {
    static let shared = PolicyStore()

    /// Compile-time baseline rules. These are enforced by the daemon first and
    /// cannot be modified through the GUI.
    @Published private(set) var baselineRules: [FAARule] = faaPolicy

    /// User-configurable rules managed by the daemon. Mutations are sent over XPC;
    /// the authoritative snapshot is pushed back via `receivedUserRules(_:)`.
    @Published private(set) var userRules: [FAARule] = []

    private init() {}

    // MARK: - Daemon push

    func receivedUserRules(_ rules: [FAARule]) {
        userRules = rules
    }

    // MARK: - Mutations (optimistic local update + XPC)

    func add(_ rule: FAARule) {
        userRules.append(rule)
        XPCClient.shared.addRule(rule)
    }

    func update(_ rule: FAARule) {
        guard let index = userRules.firstIndex(where: { $0.id == rule.id }) else { return }
        userRules[index] = rule
        XPCClient.shared.updateRule(rule)
    }

    func remove(_ rule: FAARule) {
        userRules.removeAll { $0.id == rule.id }
        XPCClient.shared.removeRule(ruleID: rule.id)
    }

    func allowProcess(teamID: String, signingID: String, inRule ruleID: UUID) {
        guard let index = userRules.firstIndex(where: { $0.id == ruleID }) else { return }
        let existing = userRules[index]
        let effectiveTeamID = teamID.isEmpty ? appleTeamID : teamID
        var newTeamIDs = existing.allowedTeamIDs
        var newSigningIDs = existing.allowedSigningIDs
        if !newTeamIDs.contains(effectiveTeamID) { newTeamIDs.append(effectiveTeamID) }
        if !signingID.isEmpty && !newSigningIDs.contains(signingID) { newSigningIDs.append(signingID) }
        let updated = FAARule(
            id: existing.id,
            protectedPathPrefix: existing.protectedPathPrefix,
            allowedProcessPaths: existing.allowedProcessPaths,
            allowedTeamIDs: newTeamIDs,
            allowedSigningIDs: newSigningIDs,
            allowedAncestorProcessPaths: existing.allowedAncestorProcessPaths,
            allowedAncestorTeamIDs: existing.allowedAncestorTeamIDs,
            allowedAncestorSigningIDs: existing.allowedAncestorSigningIDs
        )
        userRules[index] = updated
        XPCClient.shared.updateRule(updated)
    }

    func allowAncestor(teamID: String, signingID: String, inRule ruleID: UUID) {
        guard let index = userRules.firstIndex(where: { $0.id == ruleID }) else { return }
        let existing = userRules[index]
        let effectiveTeamID = teamID.isEmpty ? appleTeamID : teamID
        var newTeamIDs = existing.allowedAncestorTeamIDs
        var newSigningIDs = existing.allowedAncestorSigningIDs
        if !newTeamIDs.contains(effectiveTeamID) { newTeamIDs.append(effectiveTeamID) }
        if !signingID.isEmpty && !newSigningIDs.contains(signingID) { newSigningIDs.append(signingID) }
        let updated = FAARule(
            id: existing.id,
            protectedPathPrefix: existing.protectedPathPrefix,
            allowedProcessPaths: existing.allowedProcessPaths,
            allowedTeamIDs: existing.allowedTeamIDs,
            allowedSigningIDs: existing.allowedSigningIDs,
            allowedAncestorProcessPaths: existing.allowedAncestorProcessPaths,
            allowedAncestorTeamIDs: newTeamIDs,
            allowedAncestorSigningIDs: newSigningIDs
        )
        userRules[index] = updated
        XPCClient.shared.updateRule(updated)
    }
}
