//
//  RuleEditView.swift
//  clearancekit
//

import SwiftUI

// MARK: - RuleEditView

struct RuleEditView: View {
    private let existingID: UUID?
    @State private var draft: DraftRule
    let onSave: (FAARule) -> Void
    let onCancel: () -> Void

    init(editing rule: FAARule, onSave: @escaping (FAARule) -> Void, onCancel: @escaping () -> Void) {
        self.existingID = rule.id
        self._draft = State(initialValue: DraftRule(from: rule))
        self.onSave = onSave
        self.onCancel = onCancel
    }

    init(onSave: @escaping (FAARule) -> Void, onCancel: @escaping () -> Void) {
        self.existingID = nil
        self._draft = State(initialValue: DraftRule())
        self.onSave = onSave
        self.onCancel = onCancel
    }

    private var isValid: Bool {
        !draft.protectedPathPrefix.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section("Protected Path Prefix") {
                    TextField("/opt/example", text: $draft.protectedPathPrefix)
                        .font(.system(.body, design: .monospaced))
                }
                Section("Allowed Process Paths") {
                    StringListEditor(values: $draft.allowedProcessPaths)
                }
                Section("Allowed Team IDs") {
                    StringListEditor(values: $draft.allowedTeamIDs)
                }
                Section("Allowed Signing IDs") {
                    StringListEditor(values: $draft.allowedSigningIDs)
                }
                Section("Allowed Ancestor Process Paths") {
                    StringListEditor(values: $draft.allowedAncestorProcessPaths)
                }
                Section("Allowed Ancestor Team IDs") {
                    StringListEditor(values: $draft.allowedAncestorTeamIDs)
                }
                Section("Allowed Ancestor Signing IDs") {
                    StringListEditor(values: $draft.allowedAncestorSigningIDs)
                }
            }
            .formStyle(.grouped)

            Divider()

            HStack {
                Button("Cancel", action: onCancel)
                Spacer()
                Button("Save") {
                    onSave(draft.toRule(preservingID: existingID))
                }
                .disabled(!isValid)
                .buttonStyle(.borderedProminent)
            }
            .padding()
        }
        .frame(width: 520, height: 640)
    }
}

// MARK: - DraftRule

private struct DraftRule {
    var protectedPathPrefix: String = ""
    var allowedProcessPaths: [String] = []
    var allowedTeamIDs: [String] = []
    var allowedSigningIDs: [String] = []
    var allowedAncestorProcessPaths: [String] = []
    var allowedAncestorTeamIDs: [String] = []
    var allowedAncestorSigningIDs: [String] = []

    init() {}

    init(from rule: FAARule) {
        self.protectedPathPrefix = rule.protectedPathPrefix
        self.allowedProcessPaths = rule.allowedProcessPaths
        self.allowedTeamIDs = rule.allowedTeamIDs
        self.allowedSigningIDs = rule.allowedSigningIDs
        self.allowedAncestorProcessPaths = rule.allowedAncestorProcessPaths
        self.allowedAncestorTeamIDs = rule.allowedAncestorTeamIDs
        self.allowedAncestorSigningIDs = rule.allowedAncestorSigningIDs
    }

    func toRule(preservingID id: UUID?) -> FAARule {
        let trimmed: (String) -> String = { $0.trimmingCharacters(in: .whitespaces) }
        let nonEmpty: ([String]) -> [String] = { $0.map(trimmed).filter { !$0.isEmpty } }
        return FAARule(
            id: id ?? UUID(),
            protectedPathPrefix: trimmed(protectedPathPrefix),
            allowedProcessPaths: nonEmpty(allowedProcessPaths),
            allowedTeamIDs: nonEmpty(allowedTeamIDs),
            allowedSigningIDs: nonEmpty(allowedSigningIDs),
            allowedAncestorProcessPaths: nonEmpty(allowedAncestorProcessPaths),
            allowedAncestorTeamIDs: nonEmpty(allowedAncestorTeamIDs),
            allowedAncestorSigningIDs: nonEmpty(allowedAncestorSigningIDs)
        )
    }
}

// MARK: - StringListEditor

struct StringListEditor: View {
    @Binding var values: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(values.indices, id: \.self) { i in
                HStack {
                    TextField("", text: $values[i])
                        .font(.system(.body, design: .monospaced))
                    Button {
                        values.remove(at: i)
                    } label: {
                        Image(systemName: "minus.circle.fill")
                            .foregroundColor(.red)
                    }
                    .buttonStyle(.borderless)
                }
            }
            Button {
                values.append("")
            } label: {
                Label("Add", systemImage: "plus.circle")
            }
            .buttonStyle(.borderless)
        }
    }
}
