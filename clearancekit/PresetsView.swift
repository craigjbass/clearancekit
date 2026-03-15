//
//  PresetsView.swift
//  clearancekit
//

import SwiftUI
import UniformTypeIdentifiers

struct PresetsView: View {
    @StateObject private var policyStore = PolicyStore.shared
    @StateObject private var protectionStore = AppProtectionStore.shared
    @State private var errorMessage: String?

    var body: some View {
        List {
            Section("Custom") {
                ForEach(protectionStore.protections) { protection in
                    CustomProtectionRow(protection: protection)
                        .padding(.vertical, 6)
                }
                addApplicationButton
            }
            Section("Built-in") {
                ForEach(builtInPresets) { preset in
                    PresetRow(preset: preset, userRules: policyStore.userRules)
                        .padding(.vertical, 6)
                }
            }
        }
        .listStyle(.inset)
        .navigationTitle("App Protections")
        .onDrop(of: [.fileURL], isTargeted: nil, perform: handleDrop)
        .alert("Error", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
        }
    }

    private var addApplicationButton: some View {
        Button {
            let panel = NSOpenPanel()
            panel.canChooseFiles = true
            panel.canChooseDirectories = false
            panel.allowsMultipleSelection = false
            panel.allowedContentTypes = [.application]
            panel.directoryURL = URL(fileURLWithPath: "/Applications")
            guard panel.runModal() == .OK, let url = panel.url else { return }
            addProtection(from: url)
        } label: {
            Label("Add Application…", systemImage: "plus.app")
        }
        .buttonStyle(.borderless)
    }

    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first else { return false }
        provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, _ in
            guard let data = item as? Data,
                  let url = URL(dataRepresentation: data, relativeTo: nil),
                  url.pathExtension == "app" else { return }
            Task { @MainActor in
                addProtection(from: url)
            }
        }
        return true
    }

    private func addProtection(from url: URL) {
        Task {
            do {
                try await protectionStore.add(from: url)
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

// MARK: - CustomProtectionRow

private struct CustomProtectionRow: View {
    let protection: AppProtection
    @State private var isToggling = false

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(nsImage: protection.icon)
                .resizable()
                .frame(width: 32, height: 32)

            VStack(alignment: .leading, spacing: 4) {
                Text(protection.appName)
                    .font(.headline)
                Text(protectionSummary)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Button {
                Task { try? await AppProtectionStore.shared.remove(protection) }
            } label: {
                Image(systemName: "trash")
                    .foregroundColor(.red)
            }
            .buttonStyle(.borderless)

            Toggle("", isOn: Binding(
                get: { protection.isEnabled },
                set: { newValue in toggle(on: newValue) }
            ))
            .labelsHidden()
            .disabled(isToggling)
        }
    }

    private var protectionSummary: String {
        let count = protection.ruleIDs.count
        return count == 1 ? "1 protected path" : "\(count) protected paths"
    }

    private func toggle(on: Bool) {
        isToggling = true
        Task {
            defer { isToggling = false }
            do {
                if on {
                    try await AppProtectionStore.shared.enable(protection)
                } else {
                    try await AppProtectionStore.shared.disable(protection)
                }
            } catch {
                // Touch ID cancelled or failed — no state change needed since
                // stores only update on success.
            }
        }
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
