//
//  PresetsView.swift
//  clearancekit
//

import SwiftUI

struct PresetsView: View {
    @StateObject private var policyStore = PolicyStore.shared

    var body: some View {
        List(builtInPresets) { preset in
            PresetRow(preset: preset, userRules: policyStore.userRules)
                .padding(.vertical, 6)
        }
        .listStyle(.inset)
        .navigationTitle("App Protections")
    }
}

// MARK: - PresetRow

private struct PresetRow: View {
    let preset: AppPreset
    let userRules: [FAARule]

    @State private var isToggling = false

    private var enabledState: AppPreset.EnabledState {
        preset.enabledState(in: userRules)
    }

    private var isEnabled: Bool {
        enabledState == .enabled
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(nsImage: preset.icon)
                .resizable()
                .frame(width: 32, height: 32)

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(preset.appName)
                        .font(.headline)
                    if enabledState == .partiallyEnabled {
                        Text("partially enabled")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 2)
                            .background(Color.orange.opacity(0.15))
                            .clipShape(RoundedRectangle(cornerRadius: 3))
                    }
                }
                Text(preset.description)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()

            Toggle("", isOn: Binding(
                get: { isEnabled },
                set: { newValue in toggle(on: newValue) }
            ))
            .labelsHidden()
            .disabled(isToggling)
        }
    }

    private func toggle(on: Bool) {
        isToggling = true
        Task {
            defer { isToggling = false }
            do {
                if on {
                    try await PolicyStore.shared.addAll(preset.rules, reason: "Enable \(preset.appName) data protection")
                } else {
                    try await PolicyStore.shared.removeAll(preset.rules, reason: "Disable \(preset.appName) data protection")
                }
            } catch {
                // Touch ID cancelled or failed — no state change needed since
                // PolicyStore only updates on success.
            }
        }
    }
}
