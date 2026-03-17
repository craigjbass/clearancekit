//
//  AppProtectionStore.swift
//  clearancekit
//

import Foundation
import Combine
import os

// nonisolated(unsafe): prevents @MainActor inference on this file-scope constant.
// Logger is Sendable and immutable so this is safe.
private nonisolated(unsafe) let logger = Logger(subsystem: "uk.craigbass.clearancekit", category: "app-protection-store")

@MainActor
final class AppProtectionStore: ObservableObject {
    static let shared = AppProtectionStore()

    @Published private(set) var protections: [AppProtection] = []
    @Published private(set) var activeDiscovery: DiscoverySession? {
        didSet { forwardDiscoveryChanges() }
    }

    private let storageKey = "AppProtections"
    private var discoveryCancellable: AnyCancellable?

    private init() {
        load()
    }

    private func forwardDiscoveryChanges() {
        discoveryCancellable = activeDiscovery?.objectWillChange
            .sink { [weak self] _ in self?.objectWillChange.send() }
    }

    func add(from appURL: URL) async throws {
        guard let info = AppBundleIntrospector.inspect(appURL: appURL) else {
            throw AppProtectionError.inspectionFailed
        }

        guard !protections.contains(where: { $0.bundleID == info.bundleID }) else {
            throw AppProtectionError.alreadyExists
        }

        let rules = AppBundleIntrospector.generateRules(from: info)
        guard !rules.isEmpty else {
            activeDiscovery = DiscoverySession(appInfo: info)
            return
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

    func finalizeDiscovery(_ session: DiscoverySession) async throws {
        let rules = session.buildRules()
        precondition(!rules.isEmpty, "finalizeDiscovery called with no captured paths — button should be disabled")

        let protection = AppProtection(
            id: UUID(),
            appName: session.appInfo.appName,
            appBundlePath: session.appInfo.appPath,
            bundleID: session.appInfo.bundleID,
            ruleIDs: rules.map(\.id),
            isEnabled: true,
            snapshotRules: rules
        )

        try await PolicyStore.shared.addAll(rules, reason: "Protect \(session.appInfo.appName)")
        protections.append(protection)
        save()
        session.complete()
        activeDiscovery = nil
    }

    func cancelDiscovery() {
        activeDiscovery?.complete()
        activeDiscovery = nil
    }

    func enable(_ protection: AppProtection) async throws {
        guard let index = protections.firstIndex(where: { $0.id == protection.id }) else { return }
        guard let snapshot = protections[index].snapshotRules else { return }

        try await PolicyStore.shared.addAll(snapshot, reason: "Enable \(protection.appName) protection")
        protections[index].isEnabled = true
        save()
    }

    func disable(_ protection: AppProtection) async throws {
        guard XPCClient.shared.isConnected else { throw AppProtectionError.notConnected }
        guard let index = protections.firstIndex(where: { $0.id == protection.id }) else { return }

        // Snapshot current rules to preserve any modifications (e.g. signing IDs added from events)
        let currentRules = protections[index].ruleIDs.compactMap { ruleID in
            PolicyStore.shared.userRules.first { $0.id == ruleID }
        }
        guard currentRules.count == protections[index].ruleIDs.count else {
            throw AppProtectionError.notConnected
        }
        protections[index].snapshotRules = currentRules

        try await PolicyStore.shared.removeAll(currentRules, reason: "Disable \(protection.appName) protection")
        protections[index].isEnabled = false
        save()
    }

    func remove(_ protection: AppProtection) async throws {
        guard XPCClient.shared.isConnected else { throw AppProtectionError.notConnected }
        guard let index = protections.firstIndex(where: { $0.id == protection.id }) else { return }

        if protections[index].isEnabled {
            let currentRules = protections[index].ruleIDs.compactMap { ruleID in
                PolicyStore.shared.userRules.first { $0.id == ruleID }
            }
            guard currentRules.count == protections[index].ruleIDs.count else {
                throw AppProtectionError.notConnected
            }
            try await PolicyStore.shared.removeAll(currentRules, reason: "Remove \(protection.appName) protection")
        }

        protections.remove(at: index)
        save()
    }

    private func save() {
        do {
            let data = try JSONEncoder().encode(protections)
            UserDefaults.standard.set(data, forKey: storageKey)
        } catch {
            logger.error("AppProtectionStore: Failed to encode protections for persistence: \(error)")
        }
    }

    private func load() {
        guard let data = UserDefaults.standard.data(forKey: storageKey) else { return }
        guard let loaded = try? JSONDecoder().decode([AppProtection].self, from: data) else {
            logger.error("AppProtectionStore: Failed to decode stored protections — clearing (schema change)")
            UserDefaults.standard.removeObject(forKey: storageKey)
            return
        }
        protections = loaded
    }
}
