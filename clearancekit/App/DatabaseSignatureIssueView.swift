//
//  DatabaseSignatureIssueView.swift
//  clearancekit
//

import SwiftUI

struct DatabaseSignatureIssueView: View {
    let issue: PendingSignatureIssue
    let onResolve: (_ approved: Bool) -> Void

    @State private var isConfirmingClear = false
    @State private var isAuthenticating = false
    @State private var authError: Error? = nil

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            suspectDataList
            Divider()
            footer
        }
        .frame(width: 600, height: 480)
        .confirmationDialog(
            "Clear all user rules and allowlist entries?",
            isPresented: $isConfirmingClear,
            titleVisibility: .visible
        ) {
            Button("Clear Database", role: .destructive) {
                onResolve(false)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("All user-configured rules and allowlist entries will be permanently deleted and cannot be recovered.")
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

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .font(.title2)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                Text("Database Signature Issue Detected")
                    .font(.headline)
                Text("The stored data cannot be cryptographically verified and may have been tampered with. Review the policies below that would become active if you approve, then authenticate to sign them — or clear the database to discard all suspect data.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding()
    }

    // MARK: - Suspect data list

    @ViewBuilder
    private var suspectDataList: some View {
        if issue.suspectRules.isEmpty && issue.suspectAllowlist.isEmpty {
            VStack {
                Spacer()
                Text("No policies or allowlist entries found in the suspect data.")
                    .foregroundStyle(.secondary)
                Spacer()
            }
        } else {
            List {
                if !issue.suspectRules.isEmpty {
                    Section("Suspect Rules (\(issue.suspectRules.count))") {
                        ForEach(issue.suspectRules) { rule in
                            SuspectRuleRow(rule: rule)
                                .padding(.vertical, 4)
                        }
                    }
                }
                if !issue.suspectAllowlist.isEmpty {
                    Section("Suspect Allowlist Entries (\(issue.suspectAllowlist.count))") {
                        ForEach(issue.suspectAllowlist) { entry in
                            SuspectAllowlistEntryRow(entry: entry)
                                .padding(.vertical, 4)
                        }
                    }
                }
            }
            .listStyle(.inset)
        }
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            Button(role: .destructive) {
                isConfirmingClear = true
            } label: {
                Label("Clear Database", systemImage: "trash")
            }
            Spacer()
            Button {
                Task {
                    isAuthenticating = true
                    defer { isAuthenticating = false }
                    do {
                        try await BiometricAuth.authenticate(
                            reason: "Approve and re-sign the database contents"
                        )
                        onResolve(true)
                    } catch {
                        authError = error
                    }
                }
            } label: {
                Label(
                    isAuthenticating ? "Authenticating…" : "Approve & Sign",
                    systemImage: "touchid"
                )
            }
            .buttonStyle(.borderedProminent)
            .disabled(isAuthenticating)
        }
        .padding()
    }
}

// MARK: - SuspectRuleRow

private struct SuspectRuleRow: View {
    let rule: FAARule

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(rule.protectedPathPrefix)
                .font(.system(.body, design: .monospaced))
                .fontWeight(.semibold)
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

// MARK: - SuspectAllowlistEntryRow

private struct SuspectAllowlistEntryRow: View {
    let entry: AllowlistEntry

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                let identifier = entry.signingID.isEmpty ? entry.processPath : entry.signingID
                Text(identifier)
                    .font(.system(.body, design: .monospaced))
                if !entry.signingID.isEmpty && !entry.processPath.isEmpty {
                    Text(entry.processPath)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if entry.platformBinary {
                badge("apple")
            } else if !entry.teamID.isEmpty {
                badge(entry.teamID)
            }
        }
    }

    private func badge(_ text: String) -> some View {
        Text(text)
            .font(.caption2)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(Color.secondary.opacity(0.15))
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }
}
