//
//  PolicyExportView.swift
//  clearancekit
//

import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct PolicyExportView: View {
    let availableRules: [FAARule]
    @State private var selectedRuleIDs: Set<UUID>
    @State private var exportError: String?
    let onDismiss: () -> Void

    init(rules: [FAARule], onDismiss: @escaping () -> Void) {
        self.availableRules = rules
        self._selectedRuleIDs = State(initialValue: Set(rules.map(\.id)))
        self.onDismiss = onDismiss
    }

    private var selectedRules: [FAARule] {
        availableRules.filter { selectedRuleIDs.contains($0.id) }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ruleSelectionList
            if let error = exportError {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.caption)
                    .padding(.horizontal)
                    .padding(.bottom, 8)
            }
            Divider()
            footer
        }
        .frame(width: 520, height: 460)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Export Policy Rules")
                .font(.headline)
            Text("Select the rules you want to export. The resulting file can be shared and imported on another machine.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
    }

    private var ruleSelectionList: some View {
        List {
            ForEach(availableRules) { rule in
                HStack(alignment: .top, spacing: 10) {
                    Toggle(isOn: selectionBinding(for: rule.id)) { EmptyView() }
                        .labelsHidden()
                    VStack(alignment: .leading, spacing: 4) {
                        Text(rule.protectedPathPrefix)
                            .font(.system(.body, design: .monospaced))
                            .fontWeight(.semibold)
                        ruleDetails(for: rule)
                    }
                }
                .padding(.vertical, 4)
            }
        }
        .listStyle(.inset)
    }

    @ViewBuilder
    private func ruleDetails(for rule: FAARule) -> some View {
        if !rule.allowedSignatures.isEmpty {
            Text(rule.allowedSignatures.map(\.description).joined(separator: ", "))
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
        }
        if !rule.allowedProcessPaths.isEmpty {
            Text(rule.allowedProcessPaths.joined(separator: ", "))
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
        }
    }

    private func selectionBinding(for ruleID: UUID) -> Binding<Bool> {
        Binding(
            get: { selectedRuleIDs.contains(ruleID) },
            set: { checked in
                if checked { selectedRuleIDs.insert(ruleID) }
                else { selectedRuleIDs.remove(ruleID) }
            }
        )
    }

    private var footer: some View {
        HStack {
            Button("Cancel", action: onDismiss)
                .keyboardShortcut(.cancelAction)
            Spacer()
            Text("\(selectedRuleIDs.count) of \(availableRules.count) selected")
                .font(.caption)
                .foregroundStyle(.secondary)
            Button("Export…") { saveFile() }
                .buttonStyle(.borderedProminent)
                .disabled(selectedRuleIDs.isEmpty)
        }
        .padding()
    }

    private func saveFile() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "clearancekit-policy.json"
        panel.title = "Export Policy Rules"
        panel.message = "Choose where to save the exported policy rules."

        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            let data = try PolicyExportDocument.encode(PolicyExportDocument(rules: selectedRules))
            try data.write(to: url)
            onDismiss()
        } catch {
            exportError = "Export failed: \(error.localizedDescription)"
        }
    }
}
