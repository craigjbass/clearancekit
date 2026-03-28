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
            if selectedRulesHaveAncestry {
                ancestryWarning
            }
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

    private var selectedRulesHaveAncestry: Bool {
        selectedRules.contains { $0.requiresAncestry }
    }

    private var ancestryWarning: some View {
        HStack(spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            Text("One or more selected rules use ancestry matching. Santa's FileAccessPolicy has no equivalent — ancestry criteria will be lost in the mobileconfig export.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
    }

    private var footer: some View {
        HStack {
            Button("Cancel", action: onDismiss)
                .keyboardShortcut(.cancelAction)
            Spacer()
            Text("\(selectedRuleIDs.count) of \(availableRules.count) selected")
                .font(.caption)
                .foregroundStyle(.secondary)
            Button("Export as Santa mobileconfig…") { saveSantaMobileconfig() }
                .disabled(selectedRuleIDs.isEmpty)
            Button("Export…") { saveFile() }
                .buttonStyle(.borderedProminent)
                .disabled(selectedRuleIDs.isEmpty)
        }
        .padding()
    }

    private func saveSantaMobileconfig() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "clearancekit-santa-faa.mobileconfig"
        panel.title = "Export as Santa mobileconfig"
        panel.message = "Choose where to save the Santa FileAccessPolicy mobileconfig."

        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            let result = try SantaMobileconfigExporter.export(rules: selectedRules)
            try result.data.write(to: url)
            onDismiss()
        } catch {
            exportError = "Export failed: \(error.localizedDescription)"
        }
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
