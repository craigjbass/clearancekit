//
//  JailView.swift
//  clearancekit
//

import SwiftUI

struct JailView: View {
    @StateObject private var store = JailStore.shared

    @State private var editingRule: JailRule?
    @State private var showAddSheet = false

    var body: some View {
        VStack(spacing: 0) {
            if store.userRules.isEmpty {
                ContentUnavailableView(
                    "No Jail Rules",
                    systemImage: "lock.rectangle.on.rectangle",
                    description: Text("Jail rules restrict a process to only access a specified set of paths. Add a rule to get started.")
                )
            } else {
                List {
                    Section("User Jail Rules") {
                        ForEach(store.userRules) { rule in
                            JailRuleRow(rule: rule, onEdit: { editingRule = rule }, onDelete: {
                                Task { try? await store.remove(rule) }
                            })
                        }
                    }
                }
            }
        }
        .navigationTitle("Jail")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showAddSheet = true
                } label: {
                    Label("Add Jail Rule", systemImage: "plus")
                }
            }
        }
        .sheet(isPresented: $showAddSheet) {
            JailRuleEditView { rule in
                Task { try? await store.add(rule) }
            }
        }
        .sheet(item: $editingRule) { rule in
            JailRuleEditView(existingRule: rule) { updated in
                Task { try? await store.update(updated) }
            }
        }
    }
}

// MARK: - JailRuleRow

private struct JailRuleRow: View {
    let rule: JailRule
    let onEdit: () -> Void
    let onDelete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(rule.name)
                    .font(.headline)
                Spacer()
                Button("Edit", action: onEdit)
                Button("Delete", role: .destructive, action: onDelete)
            }
            Text("Jailed: \(rule.jailedSignature.description)")
                .font(.caption)
                .foregroundStyle(.secondary)
            if rule.allowedPathPrefixes.isEmpty {
                Text("No allowed paths — all file access denied")
                    .font(.caption)
                    .foregroundStyle(.red)
            } else {
                ForEach(rule.allowedPathPrefixes, id: \.self) { prefix in
                    Text(prefix)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - JailRuleEditView

private struct JailRuleEditView: View {
    @Environment(\.dismiss) private var dismiss

    let onSave: (JailRule) -> Void

    @State private var name: String
    @State private var teamID: String
    @State private var signingID: String
    @State private var allowedPrefixes: [String]
    @State private var newPrefix: String = ""

    private let existingID: UUID?

    init(existingRule: JailRule? = nil, onSave: @escaping (JailRule) -> Void) {
        self.onSave = onSave
        self.existingID = existingRule?.id
        _name = State(initialValue: existingRule?.name ?? "")
        _teamID = State(initialValue: existingRule?.jailedSignature.teamID ?? "")
        _signingID = State(initialValue: existingRule?.jailedSignature.signingID ?? "")
        _allowedPrefixes = State(initialValue: existingRule?.allowedPathPrefixes ?? [])
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section("Rule") {
                    TextField("Name", text: $name)
                }
                Section("Jailed Process") {
                    TextField("Team ID", text: $teamID)
                    TextField("Signing ID", text: $signingID)
                }
                Section("Allowed Path Prefixes") {
                    ForEach(allowedPrefixes, id: \.self) { prefix in
                        HStack {
                            Text(prefix)
                                .font(.body.monospaced())
                            Spacer()
                            Button {
                                allowedPrefixes.removeAll { $0 == prefix }
                            } label: {
                                Image(systemName: "minus.circle.fill")
                                    .foregroundStyle(.red)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    HStack {
                        TextField("Path prefix", text: $newPrefix)
                            .font(.body.monospaced())
                        Button("Add") {
                            guard !newPrefix.isEmpty else { return }
                            allowedPrefixes.append(newPrefix)
                            newPrefix = ""
                        }
                        .disabled(newPrefix.isEmpty)
                    }
                }
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    let rule = JailRule(
                        id: existingID ?? UUID(),
                        name: name,
                        jailedSignature: ProcessSignature(teamID: teamID, signingID: signingID),
                        allowedPathPrefixes: allowedPrefixes
                    )
                    onSave(rule)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(name.isEmpty || signingID.isEmpty)
            }
            .padding()
        }
        .frame(minWidth: 500, minHeight: 400)
    }
}
