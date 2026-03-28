//
//  PolicyImportView.swift
//  clearancekit
//

import SwiftUI

struct PolicyImportView: View {
    let rules: [FAARule]
    @State private var isImporting = false
    @State private var importError: String?
    let onImport: ([FAARule]) async throws -> Void
    let onDismiss: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            rulesPreviewList
            if let error = importError {
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
            Text("Import Policy Rules")
                .font(.headline)
            Text("The following \(rules.count) rule\(rules.count == 1 ? "" : "s") will be added to your policy. Touch ID is required to confirm.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
    }

    private var rulesPreviewList: some View {
        List {
            ForEach(rules) { rule in
                VStack(alignment: .leading, spacing: 8) {
                    Text(rule.protectedPathPrefix)
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.semibold)
                    criterionGroup("Allowed signatures", rule.allowedSignatures.map(\.description))
                    criterionGroup("Allowed process paths", rule.allowedProcessPaths)
                    criterionGroup("Allowed ancestor signatures", rule.allowedAncestorSignatures.map(\.description))
                    criterionGroup("Allowed ancestor paths", rule.allowedAncestorProcessPaths)
                }
                .padding(.vertical, 4)
            }
        }
        .listStyle(.inset)
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

    private var footer: some View {
        HStack {
            Button("Cancel", action: onDismiss)
                .keyboardShortcut(.cancelAction)
            Spacer()
            if isImporting {
                ProgressView()
                    .controlSize(.small)
            }
            Button("Import") { Task { await performImport() } }
                .buttonStyle(.borderedProminent)
                .disabled(isImporting || rules.isEmpty)
        }
        .padding()
    }

    private func performImport() async {
        isImporting = true
        defer { isImporting = false }
        do {
            try await onImport(rules)
        } catch {
            importError = "Import failed: \(error.localizedDescription)"
        }
    }
}
