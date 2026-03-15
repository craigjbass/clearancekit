//
//  PolicyView.swift
//  clearancekit
//

import SwiftUI

struct PolicyView: View {
    @StateObject private var policyStore = PolicyStore.shared
    @State private var editingRule: FAARule? = nil
    @State private var isAddingRule = false

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
    }

    private var toolbar: some View {
        HStack {
            Spacer()
            Button("Add Rule") { isAddingRule = true }
        }
        .padding()
        .background(Color(NSColor.windowBackgroundColor))
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
