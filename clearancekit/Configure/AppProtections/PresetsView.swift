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
    @State private var isUpdatingAll = false
    @State private var showAppPicker = false

    private var installedPresets: [AppPreset] {
        builtInPresets.filter(\.isInstalled)
    }

    private var appPresets: [AppPreset] {
        installedPresets.filter { $0.appBundlePath != nil }
    }

    private var systemPresets: [AppPreset] {
        installedPresets.filter { $0.appBundlePath == nil }
    }

    private var driftedPresets: [AppPreset] {
        installedPresets.filter { $0.hasDrifted(in: policyStore.userRules) }
    }

    var body: some View {
        List {
            Section("Custom") {
                ForEach(protectionStore.protections) { protection in
                    CustomProtectionRow(protection: protection)
                        .padding(.vertical, 6)
                }
                addApplicationButton
            }
            if !protectionStore.managedProtections.isEmpty {
                Section("Managed") {
                    ForEach(protectionStore.managedProtections) { protection in
                        ManagedProtectionRow(protection: protection)
                            .padding(.vertical, 6)
                    }
                }
            }
            Section("Built-in") {
                ForEach(appPresets) { preset in
                    PresetRow(preset: preset, userRules: policyStore.userRules)
                        .padding(.vertical, 6)
                }
            }
            if !systemPresets.isEmpty {
                Section("System Hardening") {
                    ForEach(systemPresets) { preset in
                        PresetRow(preset: preset, userRules: policyStore.userRules)
                            .padding(.vertical, 6)
                    }
                }
            }
        }
        .listStyle(.inset)
        .navigationTitle("App Protections")
        .toolbar {
            if !driftedPresets.isEmpty {
                ToolbarItem {
                    Button {
                        updateAll()
                    } label: {
                        Text("Update All")
                    }
                    .disabled(isUpdatingAll)
                }
            }
        }
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

    private func updateAll() {
        isUpdatingAll = true
        Task {
            defer { isUpdatingAll = false }
            do {
                let allRules = driftedPresets.flatMap(\.rules)
                try await PolicyStore.shared.updateAll(allRules, reason: "Update all app protections to latest definitions")
            } catch {
                if !BiometricAuth.isUserCancellation(error) { errorMessage = error.localizedDescription }
            }
        }
    }

    private var addApplicationButton: some View {
        Button {
            showAppPicker = true
        } label: {
            HStack {
                Label("Add Application…", systemImage: "plus.app")
                Spacer()
                Text("or drag from Finder")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .buttonStyle(.borderless)
        .sheet(isPresented: $showAppPicker) {
            AppPickerView { url in
                showAppPicker = false
                addProtection(from: url)
            } onCancel: {
                showAppPicker = false
            }
        }
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

// MARK: - DiscoverySessionRow

struct DiscoverySessionRow: View {
    @ObservedObject var session: DiscoverySession
    @State private var isFinalizing = false
    @State private var showFettle = false
    @State private var fettleDraft: ProtectionDraft?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(nsImage: NSWorkspace.shared.icon(forFile: session.appInfo.appPath))
                    .resizable()
                    .frame(width: 32, height: 32)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(session.appInfo.appName)
                            .font(.headline)
                        timerBadge
                    }
                    Text("No sandbox or app group containers found — monitoring file access")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel") {
                    AppProtectionStore.shared.cancelDiscovery()
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
            }

            if !session.isComplete {
                Text("Close and reopen \(session.appInfo.appName) to capture the folder paths it accesses.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if session.capturedPaths.isEmpty {
                if session.isComplete {
                    Text("No paths captured. The app may not have accessed any files during the session.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            } else {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(session.capturedPaths, id: \.self) { path in
                        Text(path)
                            .font(.system(.caption, design: .monospaced))
                    }
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 6))

                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Signing: \(session.appInfo.signingID)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("Team: \(session.appInfo.teamID.isEmpty ? "Apple" : session.appInfo.teamID)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Review…") {
                        fettleDraft = session.buildDraft()
                        showFettle = true
                    }
                    .disabled(isFinalizing)
                }
            }
        }
        .padding(.vertical, 6)
        .sheet(isPresented: $showFettle) {
            if let draft = fettleDraft {
                ProtectionFettleView(initialDraft: draft, saveLabel: "Create Protection") { finalDraft in
                    showFettle = false
                    isFinalizing = true
                    Task {
                        defer { isFinalizing = false }
                        try? await AppProtectionStore.shared.finalizeDiscovery(finalDraft, for: session)
                    }
                } onCancel: {
                    showFettle = false
                }
            }
        }
    }

    @ViewBuilder
    private var timerBadge: some View {
        if session.isComplete {
            Text("complete")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 5)
                .padding(.vertical, 2)
                .background(Color.secondary.opacity(0.15))
                .clipShape(RoundedRectangle(cornerRadius: 3))
        } else {
            Text("\(Int(session.timeRemaining))s")
                .font(.caption2)
                .foregroundStyle(.orange)
                .padding(.horizontal, 5)
                .padding(.vertical, 2)
                .background(Color.orange.opacity(0.15))
                .clipShape(RoundedRectangle(cornerRadius: 3))
                .monospacedDigit()
        }
    }
}

// MARK: - CustomProtectionRow

private struct CustomProtectionRow: View {
    let protection: AppProtection
    @State private var isToggling = false
    @State private var isUpdating = false
    @State private var showFettle = false
    @State private var authError: Error? = nil

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
                showFettle = true
            } label: {
                Image(systemName: "pencil")
            }
            .buttonStyle(.borderless)

            Button {
                Task {
                    do {
                        try await AppProtectionStore.shared.remove(protection)
                    } catch {
                        if !BiometricAuth.isUserCancellation(error) { authError = error }
                    }
                }
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
        .sheet(isPresented: $showFettle) {
            ProtectionFettleView(initialDraft: draftForEditing, saveLabel: "Save") { updatedDraft in
                showFettle = false
                isUpdating = true
                Task {
                    defer { isUpdating = false }
                    do {
                        try await AppProtectionStore.shared.update(protection, from: updatedDraft)
                    } catch {
                        if !BiometricAuth.isUserCancellation(error) { authError = error }
                    }
                }
            } onCancel: {
                showFettle = false
            }
        }
        .alert("Authentication Failed", isPresented: Binding(
            get: { authError != nil },
            set: { if !$0 { authError = nil } }
        )) {
            Button("OK") { authError = nil }
        } message: {
            if let error = authError {
                Text(error.localizedDescription)
            }
        }
    }

    private var protectionSummary: String {
        let count = protection.ruleIDs.count
        return count == 1 ? "1 protected path" : "\(count) protected paths"
    }

    private var draftForEditing: ProtectionDraft {
        let currentRules = protection.ruleIDs.compactMap { ruleID in
            PolicyStore.shared.userRules.first { $0.id == ruleID }
        }
        let rules = currentRules.isEmpty ? (protection.snapshotRules ?? []) : currentRules
        let info = AppBundleInfo(
            appName: protection.appName,
            bundleID: protection.bundleID,
            appPath: protection.appBundlePath,
            teamID: "",
            signingID: "",
            appGroups: [],
            isSandboxed: false
        )
        return ProtectionDraft.from(rules: rules, appInfo: info)
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
                if !BiometricAuth.isUserCancellation(error) { authError = error }
            }
        }
    }
}

// MARK: - ManagedProtectionRow

private struct ManagedProtectionRow: View {
    let protection: AppProtection

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(nsImage: protection.icon)
                .resizable()
                .frame(width: 32, height: 32)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(protection.appName)
                        .font(.headline)
                    managedBadge
                }
                Text(protectionSummary)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
    }

    private var protectionSummary: String {
        let count = protection.ruleIDs.count
        return "\(count) protected \(count == 1 ? "path" : "paths")"
    }

    private var managedBadge: some View {
        Text("managed")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(Color.secondary.opacity(0.15))
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }
}

// MARK: - PresetRow

private struct PresetRow: View {
    let preset: AppPreset
    let userRules: [FAARule]

    @State private var isToggling = false
    @State private var isUpdating = false
    @State private var authError: Error? = nil

    private var enabledState: AppPreset.EnabledState {
        preset.enabledState(in: userRules)
    }

    private var isEnabled: Bool {
        enabledState == .enabled
    }

    private var hasDrifted: Bool {
        preset.hasDrifted(in: userRules)
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
                        badge("partially enabled", color: .orange)
                    }
                    if hasDrifted {
                        badge("update available", color: .blue)
                    }
                    if preset.isExperimental {
                        badge("experimental", color: .purple)
                    }
                }
                Text(preset.description)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()

            if hasDrifted {
                Button("Update") { update() }
                    .buttonStyle(.borderless)
                    .disabled(isUpdating)
            }

            Toggle("", isOn: Binding(
                get: { isEnabled },
                set: { newValue in toggle(on: newValue) }
            ))
            .labelsHidden()
            .disabled(isToggling)
        }
        .alert("Authentication Failed", isPresented: Binding(
            get: { authError != nil },
            set: { if !$0 { authError = nil } }
        )) {
            Button("OK") { authError = nil }
        } message: {
            if let error = authError {
                Text(error.localizedDescription)
            }
        }
    }

    private func badge(_ label: String, color: Color) -> some View {
        Text(label)
            .font(.caption2)
            .foregroundStyle(color)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .clipShape(RoundedRectangle(cornerRadius: 3))
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
                if !BiometricAuth.isUserCancellation(error) { authError = error }
            }
        }
    }

    private func update() {
        isUpdating = true
        Task {
            defer { isUpdating = false }
            do {
                try await PolicyStore.shared.updateAll(preset.rules, reason: "Update \(preset.appName) data protection to latest definition")
            } catch {
                if !BiometricAuth.isUserCancellation(error) { authError = error }
            }
        }
    }
}
