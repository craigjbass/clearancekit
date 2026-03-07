//
//  PolicyStore.swift
//  clearancekit
//

import Foundation
import Combine

/// Vends the active FAA rules to the UI.
///
/// Currently backed by the hardcoded `faaPolicy` constant. Designed so that
/// future dynamic sources (file-based config, XPC delivery from the daemon, etc.)
/// can be wired in by updating `rules` here without touching any views.
@MainActor
final class PolicyStore: ObservableObject {
    static let shared = PolicyStore()

    @Published private(set) var rules: [FAARule] = faaPolicy

    private init() {}
}
