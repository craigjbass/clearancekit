//
//  PolicyStore.swift
//  clearancekit
//

import Foundation
import Combine

/// Vends and persists the active FAA rules.
///
/// Currently seeded from the compile-time `faaPolicy` constant on first launch,
/// then persisted to JSON in Application Support. Future dynamic sources
/// (XPC delivery, remote config) slot in here without touching any views.
@MainActor
final class PolicyStore: ObservableObject {
    static let shared = PolicyStore()

    @Published private(set) var rules: [FAARule]

    private let storageURL: URL
    private var cancellable: AnyCancellable?

    private init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = appSupport.appendingPathComponent("clearancekit")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("policy.json")
        self.storageURL = url

        if let data = try? Data(contentsOf: url),
           let decoded = try? JSONDecoder().decode([FAARule].self, from: data) {
            self.rules = decoded
        } else {
            self.rules = faaPolicy
        }

        cancellable = XPCClient.shared.$isConnected
            .filter { $0 }
            .sink { [weak self] _ in
                guard let self else { return }
                XPCClient.shared.updatePolicy(rules: self.rules)
            }
    }

    func add(_ rule: FAARule) {
        rules.append(rule)
        save()
    }

    func update(_ rule: FAARule) {
        guard let index = rules.firstIndex(where: { $0.id == rule.id }) else { return }
        rules[index] = rule
        save()
    }

    func remove(_ rule: FAARule) {
        rules.removeAll { $0.id == rule.id }
        save()
    }

    /// Adds the process's team ID and signing ID to the allowedTeamIDs / allowedSigningIDs
    /// of the most specific rule whose prefix matches `path`.
    func allowProcess(teamID: String, signingID: String, inRuleMatching path: String) {
        guard let index = bestMatchingRuleIndex(for: path) else { return }
        let existing = rules[index]
        let effectiveTeamID = teamID.isEmpty ? appleTeamID : teamID
        var newTeamIDs = existing.allowedTeamIDs
        var newSigningIDs = existing.allowedSigningIDs
        if !newTeamIDs.contains(effectiveTeamID) { newTeamIDs.append(effectiveTeamID) }
        if !signingID.isEmpty && !newSigningIDs.contains(signingID) { newSigningIDs.append(signingID) }
        rules[index] = FAARule(
            id: existing.id,
            protectedPathPrefix: existing.protectedPathPrefix,
            allowedProcessPaths: existing.allowedProcessPaths,
            allowedTeamIDs: newTeamIDs,
            allowedSigningIDs: newSigningIDs,
            allowedAncestorProcessPaths: existing.allowedAncestorProcessPaths,
            allowedAncestorTeamIDs: existing.allowedAncestorTeamIDs,
            allowedAncestorSigningIDs: existing.allowedAncestorSigningIDs
        )
        save()
    }

    /// Adds the ancestor's team ID and signing ID to the allowedAncestorTeamIDs /
    /// allowedAncestorSigningIDs of the most specific rule whose prefix matches `path`.
    func allowAncestor(teamID: String, signingID: String, inRuleMatching path: String) {
        guard let index = bestMatchingRuleIndex(for: path) else { return }
        let existing = rules[index]
        let effectiveTeamID = teamID.isEmpty ? appleTeamID : teamID
        var newTeamIDs = existing.allowedAncestorTeamIDs
        var newSigningIDs = existing.allowedAncestorSigningIDs
        if !newTeamIDs.contains(effectiveTeamID) { newTeamIDs.append(effectiveTeamID) }
        if !signingID.isEmpty && !newSigningIDs.contains(signingID) { newSigningIDs.append(signingID) }
        rules[index] = FAARule(
            id: existing.id,
            protectedPathPrefix: existing.protectedPathPrefix,
            allowedProcessPaths: existing.allowedProcessPaths,
            allowedTeamIDs: existing.allowedTeamIDs,
            allowedSigningIDs: existing.allowedSigningIDs,
            allowedAncestorProcessPaths: existing.allowedAncestorProcessPaths,
            allowedAncestorTeamIDs: newTeamIDs,
            allowedAncestorSigningIDs: newSigningIDs
        )
        save()
    }

    private func bestMatchingRuleIndex(for path: String) -> Int? {
        rules.indices
            .filter { path.hasPrefix(rules[$0].protectedPathPrefix) }
            .max(by: { rules[$0].protectedPathPrefix.count < rules[$1].protectedPathPrefix.count })
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(rules) else { return }
        try? data.write(to: storageURL, options: .atomic)
        XPCClient.shared.updatePolicy(rules: rules)
    }
}
