//
//  AppProtectionStore.swift
//  clearancekit
//

import Foundation
import Combine

@MainActor
final class AppProtectionStore: ObservableObject {
    static let shared = AppProtectionStore()

    @Published private(set) var protections: [AppProtection] = []

    private let storageKey = "AppProtections"

    private init() {
        load()
    }

    func add(from appURL: URL) async throws {
        guard let info = AppBundleIntrospector.inspect(appURL: appURL) else {
            throw AppProtectionError.inspectionFailed
        }

        let rules = AppBundleIntrospector.generateRules(from: info)
        guard !rules.isEmpty else {
            throw AppProtectionError.noProtectablePaths
        }

        guard !protections.contains(where: { $0.bundleID == info.bundleID }) else {
            throw AppProtectionError.alreadyExists
        }

        let protection = AppProtection(
            id: UUID(),
            appName: info.appName,
            appBundlePath: info.appPath,
            bundleID: info.bundleID,
            ruleIDs: rules.map(\.id),
            isEnabled: true,
            snapshotRules: rules
        )

        try await PolicyStore.shared.addAll(rules, reason: "Protect \(info.appName)")
        protections.append(protection)
        save()
    }

    func enable(_ protection: AppProtection) async throws {
        guard let index = protections.firstIndex(where: { $0.id == protection.id }) else { return }
        guard let snapshot = protections[index].snapshotRules else { return }

        try await PolicyStore.shared.addAll(snapshot, reason: "Enable \(protection.appName) protection")
        protections[index].isEnabled = true
        save()
    }

    func disable(_ protection: AppProtection) async throws {
        guard let index = protections.firstIndex(where: { $0.id == protection.id }) else { return }

        // Snapshot current rules to preserve any modifications (e.g. signing IDs added from events)
        let currentRules = protections[index].ruleIDs.compactMap { ruleID in
            PolicyStore.shared.userRules.first { $0.id == ruleID }
        }
        protections[index].snapshotRules = currentRules

        try await PolicyStore.shared.removeAll(currentRules, reason: "Disable \(protection.appName) protection")
        protections[index].isEnabled = false
        save()
    }

    func remove(_ protection: AppProtection) async throws {
        guard let index = protections.firstIndex(where: { $0.id == protection.id }) else { return }

        if protections[index].isEnabled {
            let currentRules = protections[index].ruleIDs.compactMap { ruleID in
                PolicyStore.shared.userRules.first { $0.id == ruleID }
            }
            try await PolicyStore.shared.removeAll(currentRules, reason: "Remove \(protection.appName) protection")
        }

        protections.remove(at: index)
        save()
    }

    private func save() {
        let data = try! JSONEncoder().encode(protections)
        UserDefaults.standard.set(data, forKey: storageKey)
    }

    private func load() {
        guard let data = UserDefaults.standard.data(forKey: storageKey) else { return }
        protections = try! JSONDecoder().decode([AppProtection].self, from: data)
    }
}
