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

    private func save() {
        guard let data = try? JSONEncoder().encode(rules) else { return }
        try? data.write(to: storageURL, options: .atomic)
        XPCClient.shared.updatePolicy(rules: rules)
    }
}
