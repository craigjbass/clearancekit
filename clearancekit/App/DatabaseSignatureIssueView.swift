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
            "Clear all suspect data?",
            isPresented: $isConfirmingClear,
            titleVisibility: .visible
        ) {
            Button("Clear Database", role: .destructive) {
                onResolve(false)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("All suspect rules, allowlist entries, quiet list entries, jail rules and updater signatures will be permanently deleted and cannot be recovered. Suspect settings return to their protective defaults.")
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
                Text("The stored data cannot be cryptographically verified and may have been tampered with. Review everything below that would become active if you approve, then authenticate to sign it — or clear the database to discard all suspect data.")
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
        if issue.hasNoSuspectEntries {
            VStack {
                Spacer()
                Text("No rules, allowlist entries or settings found in the suspect data.")
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
                            SuspectProcessEntryRow(
                                signingID: entry.signingID,
                                processPath: entry.processPath,
                                platformBinary: entry.platformBinary,
                                teamID: entry.teamID
                            )
                            .padding(.vertical, 4)
                        }
                    }
                }
                if !issue.suspectAncestorAllowlist.isEmpty {
                    Section("Suspect Ancestor Allowlist Entries (\(issue.suspectAncestorAllowlist.count))") {
                        ForEach(issue.suspectAncestorAllowlist) { entry in
                            SuspectProcessEntryRow(
                                signingID: entry.signingID,
                                processPath: entry.processPath,
                                platformBinary: entry.platformBinary,
                                teamID: entry.teamID
                            )
                            .padding(.vertical, 4)
                        }
                    }
                }
                if !issue.suspectQuietList.isEmpty {
                    Section("Suspect Quiet List Entries (\(issue.suspectQuietList.count))") {
                        ForEach(issue.suspectQuietList) { entry in
                            SuspectProcessEntryRow(
                                signingID: entry.signingID,
                                processPath: entry.processPath,
                                platformBinary: entry.platformBinary,
                                teamID: entry.teamID
                            )
                            .padding(.vertical, 4)
                        }
                    }
                }
                if !issue.suspectJailRules.isEmpty {
                    Section("Suspect Jail Rules (\(issue.suspectJailRules.count))") {
                        ForEach(issue.suspectJailRules) { rule in
                            SuspectJailRuleRow(rule: rule)
                                .padding(.vertical, 4)
                        }
                    }
                }
                if !issue.suspectBundleUpdaterSignatures.isEmpty {
                    Section("Suspect Updater Signatures (\(issue.suspectBundleUpdaterSignatures.count))") {
                        ForEach(issue.suspectBundleUpdaterSignatures) { signature in
                            Text("\(signature.teamID):\(signature.signingID)")
                                .font(.system(.body, design: .monospaced))
                                .padding(.vertical, 4)
                        }
                    }
                }
                if !issue.suspectFeatureFlags.isEmpty {
                    Section("Suspect Settings (\(issue.suspectFeatureFlags.count))") {
                        ForEach(issue.suspectFeatureFlags, id: \.id) { flag in
                            HStack {
                                Text(flag.name)
                                    .font(.system(.body, design: .monospaced))
                                Spacer()
                                Text(flag.enabled ? "On" : "Off")
                                    .foregroundStyle(.secondary)
                            }
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

// MARK: - SuspectJailRuleRow

private struct SuspectJailRuleRow: View {
    let rule: JailRule

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(rule.name)
                .fontWeight(.semibold)
            Text(rule.jailedSignature.description)
                .font(.system(.caption, design: .monospaced))
            if !rule.allowedPathPrefixes.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Allowed path prefixes")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    ForEach(rule.allowedPathPrefixes, id: \.self) { prefix in
                        Text(prefix)
                            .font(.system(.caption, design: .monospaced))
                    }
                }
            }
        }
    }
}

// MARK: - SuspectProcessEntryRow

private struct SuspectProcessEntryRow: View {
    let signingID: String
    let processPath: String
    let platformBinary: Bool
    let teamID: String

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(signingID.isEmpty ? processPath : signingID)
                    .font(.system(.body, design: .monospaced))
                if !signingID.isEmpty && !processPath.isEmpty {
                    Text(processPath)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if platformBinary {
                badge("apple")
            } else if !teamID.isEmpty {
                badge(teamID)
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
