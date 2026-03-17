//
//  PolicyView.swift
//  clearancekit
//

import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct PolicyView: View {
    @StateObject private var policyStore = PolicyStore.shared
    @State private var editingRule: FAARule? = nil
    @State private var isAddingRule = false
    @State private var isExporting = false
    @State private var importPreview: ImportPreviewItem? = nil
    @State private var importError: String? = nil

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
                    } catch {}
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
                    } catch {}
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
            let importedRules = document.rules.map(\.reimportedWithNewID)
            guard !importedRules.isEmpty else {
                importError = "The selected file contains no rules."
                return
            }
            importPreview = ImportPreviewItem(rules: importedRules)
        } catch {
            importError = "Could not read the selected file: \(error.localizedDescription)"
        }
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
                            RuleRow(rule: rule, isEditable: false) { } onDelete: { }
                                .padding(.vertical, 4)
                        }
                    }
                }
                if !policyStore.managedRules.isEmpty {
                    Section("Managed Profile Rules") {
                        ForEach(policyStore.managedRules) { rule in
                            RuleRow(rule: rule, isEditable: false) { } onDelete: { }
                                .padding(.vertical, 4)
                        }
                    }
                }
                if !policyStore.userRules.isEmpty {
                    Section("User Rules") {
                        ForEach(policyStore.userRules) { rule in
                            RuleRow(rule: rule, isEditable: true) {
                                editingRule = rule
                            } onDelete: {
                                Task { try? await policyStore.remove(rule) }
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

// MARK: - FAARule import helper

private extension FAARule {
    /// Returns a copy of the receiver with a fresh UUID, forced to the `.user` source tier.
    /// Used when importing rules so each import produces an independent rule entry.
    var reimportedWithNewID: FAARule {
        FAARule(
            protectedPathPrefix: protectedPathPrefix,
            source: .user,
            allowedProcessPaths: allowedProcessPaths,
            allowedSignatures: allowedSignatures,
            allowedAncestorProcessPaths: allowedAncestorProcessPaths,
            allowedAncestorSignatures: allowedAncestorSignatures
        )
    }
}
