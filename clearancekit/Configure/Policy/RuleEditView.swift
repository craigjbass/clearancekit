//
//  RuleEditView.swift
//  clearancekit
//

import SwiftUI

// MARK: - RuleEditView

private enum ProcessPickerTarget: Identifiable, Hashable {
    case process
    case signature
    case ancestor
    case ancestorSignature
    var id: Self { self }
}

struct RuleEditView: View {
    private let existingID: UUID?
    @State private var draft: DraftRule
    @State private var processPicker: ProcessPickerTarget?
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

    init(prefilledFrom process: RunningProcessInfo, onSave: @escaping (FAARule) -> Void, onCancel: @escaping () -> Void) {
        self.existingID = nil
        let effectiveTeamID = process.teamID.isEmpty ? appleTeamID : process.teamID
        let sig = "\(effectiveTeamID):\(process.signingID.isEmpty ? "*" : process.signingID)"
        var draft = DraftRule()
        if !process.path.isEmpty { draft.allowedProcessPaths = [process.path] }
        if !process.signingID.isEmpty { draft.allowedSignatures = [sig] }
        self._draft = State(initialValue: draft)
        self.onSave = onSave
        self.onCancel = onCancel
    }

    private var isValid: Bool {
        !draft.protectedPathPrefix.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("/opt/example  or  /Users/*/Documents", text: $draft.protectedPathPrefix)
                        .font(.system(.body, design: .monospaced))
                } header: {
                    Text("Protected Path")
                } footer: {
                    Text("Protects all files and subdirectories within the specified directory. Use * to match any single path component, ** to match any number of levels.")
                        .foregroundStyle(.secondary)
                }
                Section {
                    StringListEditor(values: $draft.allowedProcessPaths)
                } header: {
                    pickerSectionHeader("Allowed Process Paths", target: .process)
                }
                Section {
                    StringListEditor(values: $draft.allowedSignatures, placeholder: "teamID:signingID")
                } header: {
                    pickerSectionHeader("Allowed Signatures", target: .signature)
                }
                Section {
                    StringListEditor(values: $draft.allowedAncestorProcessPaths)
                } header: {
                    pickerSectionHeader("Allowed Ancestor Process Paths", target: .ancestor)
                } footer: {
                    ancestryWarning
                }
                Section {
                    StringListEditor(values: $draft.allowedAncestorSignatures, placeholder: "teamID:signingID")
                } header: {
                    pickerSectionHeader("Allowed Ancestor Signatures", target: .ancestorSignature)
                }
                Section {
                    Toggle("Only enforce on writes", isOn: $draft.enforceOnWriteOnly)
                } footer: {
                    Text("When enabled, this rule only blocks operations that modify files (writes, renames, deletions, etc.). Any process may read the protected files. Use this for tamper-protection of config files where read access is not sensitive.")
                        .foregroundStyle(.secondary)
                }
                Section {
                    Toggle("Require valid code signature", isOn: $draft.requireValidSigning)
                } footer: {
                    Text("When enabled, unsigned and ad-hoc-signed processes are denied even if they match a wildcard rule.")
                        .foregroundStyle(.secondary)
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
        .sheet(item: $processPicker) { target in
            ProcessPickerView { process in
                let effectiveTeamID = process.teamID.isEmpty ? appleTeamID : process.teamID
                let sig = "\(effectiveTeamID):\(process.signingID.isEmpty ? "*" : process.signingID)"
                switch target {
                case .process:
                    if !process.path.isEmpty { draft.allowedProcessPaths.append(process.path) }
                    draft.allowedSignatures.append(sig)
                case .signature:
                    draft.allowedSignatures.append(sig)
                case .ancestor:
                    if !process.path.isEmpty { draft.allowedAncestorProcessPaths.append(process.path) }
                    draft.allowedAncestorSignatures.append(sig)
                case .ancestorSignature:
                    draft.allowedAncestorSignatures.append(sig)
                }
                processPicker = nil
            } onCancel: {
                processPicker = nil
            }
        }
    }

    private var hasAncestorCriteria: Bool {
        !draft.allowedAncestorProcessPaths.isEmpty || !draft.allowedAncestorSignatures.isEmpty
    }

    @ViewBuilder
    private var ancestryWarning: some View {
        if hasAncestorCriteria {
            Label("Ancestry rules require process tree lookups which are more CPU intensive. Use a narrow protected path to minimise performance impact.", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        }
    }

    @ViewBuilder
    private func pickerSectionHeader(_ title: String, target: ProcessPickerTarget) -> some View {
        HStack {
            Text(title)
            Spacer()
            Button("Pick from running processes...") { processPicker = target }
                .font(.caption)
                .buttonStyle(.borderless)
        }
    }
}

// MARK: - DraftRule

private struct DraftRule {
    var protectedPathPrefix: String = ""
    var allowedProcessPaths: [String] = []
    var allowedSignatures: [String] = []
    var allowedAncestorProcessPaths: [String] = []
    var allowedAncestorSignatures: [String] = []
    var enforceOnWriteOnly: Bool = false
    var requireValidSigning: Bool = false

    init() {}

    init(from rule: FAARule) {
        self.protectedPathPrefix = rule.protectedPathPrefix
        self.allowedProcessPaths = rule.allowedProcessPaths
        self.allowedSignatures = rule.allowedSignatures.map(\.description)
        self.allowedAncestorProcessPaths = rule.allowedAncestorProcessPaths
        self.allowedAncestorSignatures = rule.allowedAncestorSignatures.map(\.description)
        self.enforceOnWriteOnly = rule.enforceOnWriteOnly
        self.requireValidSigning = rule.requireValidSigning
    }

    func toRule(preservingID id: UUID?) -> FAARule {
        let trimmed: (String) -> String = { $0.trimmingCharacters(in: .whitespaces) }
        let nonEmpty: ([String]) -> [String] = { $0.map(trimmed).filter { !$0.isEmpty } }
        let parseSignature: (String) -> ProcessSignature? = { s in
            guard let colonIndex = s.firstIndex(of: ":") else { return nil }
            return ProcessSignature(
                teamID: String(s[s.startIndex..<colonIndex]),
                signingID: String(s[s.index(after: colonIndex)...])
            )
        }
        return FAARule(
            id: id ?? UUID(),
            protectedPathPrefix: trimmed(protectedPathPrefix),
            allowedProcessPaths: nonEmpty(allowedProcessPaths),
            allowedSignatures: nonEmpty(allowedSignatures).compactMap(parseSignature),
            allowedAncestorProcessPaths: nonEmpty(allowedAncestorProcessPaths),
            allowedAncestorSignatures: nonEmpty(allowedAncestorSignatures).compactMap(parseSignature),
            enforceOnWriteOnly: enforceOnWriteOnly,
            requireValidSigning: requireValidSigning
        )
    }
}

// MARK: - StringListEditor

struct StringListEditor: View {
    @Binding var values: [String]
    var placeholder: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(values.indices, id: \.self) { i in
                HStack {
                    TextField(placeholder, text: $values[i])
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
