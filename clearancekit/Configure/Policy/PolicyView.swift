//
//  PolicyView.swift
//  clearancekit
//

import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct PolicyView: View {
    @StateObject private var policyStore = PolicyStore.shared
    @StateObject private var protectionStore = AppProtectionStore.shared
    @State private var editingRule: FAARule? = nil
    @State private var isAddingRule = false
    @State private var isExporting = false
    @State private var importPreview: ImportPreviewItem? = nil
    @State private var importError: String? = nil
    @State private var authError: Error? = nil

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            ruleList
        }
        .sheet(item: $editingRule) { rule in
            RuleEditView(editing: rule) { updated in
                Task {
                    do {
                        try await policyStore.update(updated)
                        editingRule = nil
                    } catch {
                        if !BiometricAuth.isUserCancellation(error) { authError = error }
                    }
                }
            } onCancel: {
                editingRule = nil
            }
        }
        .sheet(isPresented: $isAddingRule) {
            RuleEditView { rule in
                Task {
                    do {
                        try await policyStore.add(rule)
                        isAddingRule = false
                    } catch {
                        if !BiometricAuth.isUserCancellation(error) { authError = error }
                    }
                }
            } onCancel: {
                isAddingRule = false
            }
        }
        .sheet(isPresented: $isExporting) {
            PolicyExportView(rules: policyStore.userRules) {
                isExporting = false
            }
        }
        .sheet(item: $importPreview) { preview in
            PolicyImportView(rules: preview.rules) { rules in
                try await policyStore.addAll(rules, reason: "Import policy rules")
                importPreview = nil
            } onDismiss: {
                importPreview = nil
            }
        }
        .alert("Import Failed", isPresented: Binding(
            get: { importError != nil },
            set: { if !$0 { importError = nil } }
        )) {
            Button("OK") { importError = nil }
        } message: {
            Text(importError ?? "")
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

    private var toolbar: some View {
        HStack {
            Button("Import Rules…") { openImportPanel() }
            Spacer()
            Button("Export Rules…") { isExporting = true }
                .disabled(policyStore.userRules.isEmpty)
            Button("Add Rule") { isAddingRule = true }
        }
        .padding()
        .background(Color(NSColor.windowBackgroundColor))
    }

    private func openImportPanel() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        panel.title = "Import Policy Rules"
        panel.message = "Select a clearancekit policy export file."

        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            let data = try Data(contentsOf: url)
            let document = try PolicyExportDocument.decode(from: data)
            guard !document.rules.isEmpty else {
                importError = "The selected file contains no rules."
                return
            }
            importPreview = ImportPreviewItem(rules: document.rules)
        } catch {
            importError = "Could not read the selected file: \(error.localizedDescription)"
        }
    }

    private func source(for rule: FAARule) -> (name: String, icon: NSImage)? {
        let allProtections = protectionStore.protections + protectionStore.managedProtections
        if let protection = allProtections.first(where: { $0.ruleIDs.contains(rule.id) }) {
            return (protection.appName, protection.icon)
        }
        if let preset = builtInPresets.first(where: { $0.rules.contains { $0.id == rule.id } }) {
            return (preset.appName, preset.icon)
        }
        return nil
    }

    @ViewBuilder
    private var ruleList: some View {
        if policyStore.baselineRules.isEmpty && policyStore.userRules.isEmpty {
            VStack {
                Spacer()
                Text("No rules configured")
                    .foregroundStyle(.secondary)
                Spacer()
            }
        } else {
            List {
                if !policyStore.baselineRules.isEmpty {
                    Section("Baseline Rules") {
                        ForEach(policyStore.baselineRules) { rule in
                            RuleRow(rule: rule, source: nil, isEditable: false) { } onDelete: { }
                                .padding(.vertical, 4)
                        }
                    }
                }
                if !policyStore.managedRules.isEmpty {
                    Section("Managed Profile Rules") {
                        ForEach(policyStore.managedRules) { rule in
                            RuleRow(rule: rule, source: source(for: rule), isEditable: false) { } onDelete: { }
                                .padding(.vertical, 4)
                        }
                    }
                }
                if !policyStore.userRules.isEmpty {
                    Section("User Rules") {
                        ForEach(policyStore.userRules) { rule in
                            RuleRow(rule: rule, source: source(for: rule), isEditable: true) {
                                editingRule = rule
                            } onDelete: {
                                Task {
                                    do {
                                        try await policyStore.remove(rule)
                                    } catch {
                                        if !BiometricAuth.isUserCancellation(error) { authError = error }
                                    }
                                }
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }
            }
            .listStyle(.inset)
        }
    }
}

// MARK: - ImportPreviewItem

private struct ImportPreviewItem: Identifiable {
    let id = UUID()
    let rules: [FAARule]
}

// MARK: - RuleRow

private struct RuleRow: View {
    let rule: FAARule
    let source: (name: String, icon: NSImage)?
    let isEditable: Bool
    let onEdit: () -> Void
    let onDelete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(rule.protectedPathPrefix)
                    .font(.system(.body, design: .monospaced))
                    .fontWeight(.semibold)
                if !isEditable {
                    Text("baseline")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                }
                Spacer()
                if let source {
                    HStack(spacing: 4) {
                        Image(nsImage: source.icon)
                            .resizable()
                            .frame(width: 16, height: 16)
                        Text(source.name)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                if isEditable {
                    Button { onEdit() } label: {
                        Image(systemName: "pencil")
                    }
                    .buttonStyle(.borderless)
                    Button { onDelete() } label: {
                        Image(systemName: "trash")
                            .foregroundColor(.red)
                    }
                    .buttonStyle(.borderless)
                }
            }

            criterionGroup("Allowed process paths", rule.allowedProcessPaths)
            criterionGroup("Allowed signatures", rule.allowedSignatures.map(\.description))
            criterionGroup("Allowed ancestor paths", rule.allowedAncestorProcessPaths)
            criterionGroup("Allowed ancestor signatures", rule.allowedAncestorSignatures.map(\.description))
        }
    }

    @ViewBuilder
    private func criterionGroup(_ label: String, _ values: [String]) -> some View {
        if !values.isEmpty {
            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                ForEach(values, id: \.self) { value in
                    Text(value)
                        .font(.system(.caption, design: .monospaced))
                }
            }
        }
    }
}
