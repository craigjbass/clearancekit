//
//  AllowlistView.swift
//  clearancekit
//

import SwiftUI

struct AllowlistView: View {
    @StateObject private var allowlistStore = AllowlistStore.shared
    @State private var isAddingEntry = false
    @State private var isAddingAncestorEntry = false
    @State private var editingEntry: AllowlistEntry? = nil
    @State private var editingAncestorEntry: AncestorAllowlistEntry? = nil
    @State private var authError: Error? = nil

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            entryList
        }
        .sheet(isPresented: $isAddingEntry) {
            AllowlistEntryEditView { entry in
                Task {
                    do {
                        try await allowlistStore.add(entry)
                        isAddingEntry = false
                    } catch {
                        if !BiometricAuth.isUserCancellation(error) { authError = error }
                    }
                }
            } onCancel: {
                isAddingEntry = false
            }
        }
        .sheet(isPresented: $isAddingAncestorEntry) {
            AncestorAllowlistEntryEditView { entry in
                Task {
                    do {
                        try await allowlistStore.addAncestor(entry)
                        isAddingAncestorEntry = false
                    } catch {
                        if !BiometricAuth.isUserCancellation(error) { authError = error }
                    }
                }
            } onCancel: {
                isAddingAncestorEntry = false
            }
        }
        .sheet(item: $editingEntry) { entry in
            AllowlistEntryEditView(existing: entry) { updated in
                Task {
                    do {
                        try await allowlistStore.update(updated)
                        editingEntry = nil
                    } catch {
                        if !BiometricAuth.isUserCancellation(error) { authError = error }
                    }
                }
            } onCancel: {
                editingEntry = nil
            }
        }
        .sheet(item: $editingAncestorEntry) { entry in
            AncestorAllowlistEntryEditView(existing: entry) { updated in
                Task {
                    do {
                        try await allowlistStore.updateAncestor(updated)
                        editingAncestorEntry = nil
                    } catch {
                        if !BiometricAuth.isUserCancellation(error) { authError = error }
                    }
                }
            } onCancel: {
                editingAncestorEntry = nil
            }
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

    private var toolbar: some View {
        HStack {
            Spacer()
            Button("Add Ancestor Entry") { isAddingAncestorEntry = true }
            Button("Add Entry") { isAddingEntry = true }
        }
        .padding()
        .background(Color(NSColor.windowBackgroundColor))
    }

    @ViewBuilder
    private var entryList: some View {
        List {
            if !allowlistStore.baselineEntries.isEmpty {
                Section("Baseline Entries") {
                    ForEach(allowlistStore.baselineEntries) { entry in
                        AllowlistEntryRow(entry: entry, source: .baseline, isEditable: false, onEdit: { }, onDelete: { })
                            .padding(.vertical, 4)
                    }
                }
            }
            if !allowlistStore.managedEntries.isEmpty {
                Section("Managed Profile Entries") {
                    ForEach(allowlistStore.managedEntries) { entry in
                        AllowlistEntryRow(entry: entry, source: .managed, isEditable: false, onEdit: { }, onDelete: { })
                            .padding(.vertical, 4)
                    }
                }
            }
            if !allowlistStore.userEntries.isEmpty {
                Section("User Entries") {
                    ForEach(allowlistStore.userEntries) { entry in
                        AllowlistEntryRow(entry: entry, source: .user, isEditable: true, onEdit: {
                            editingEntry = entry
                        }, onDelete: {
                            Task {
                                do {
                                    try await allowlistStore.remove(entry)
                                } catch {
                                    if !BiometricAuth.isUserCancellation(error) { authError = error }
                                }
                            }
                        })
                        .padding(.vertical, 4)
                    }
                }
            }
            if !allowlistStore.managedAncestorEntries.isEmpty {
                Section("Managed Profile Ancestor Entries") {
                    ForEach(allowlistStore.managedAncestorEntries) { entry in
                        AncestorAllowlistEntryRow(entry: entry, isEditable: false, onEdit: { }, onDelete: { })
                            .padding(.vertical, 4)
                    }
                }
            }
            if !allowlistStore.userAncestorEntries.isEmpty {
                Section("User Ancestor Entries") {
                    ForEach(allowlistStore.userAncestorEntries) { entry in
                        AncestorAllowlistEntryRow(entry: entry, isEditable: true, onEdit: {
                            editingAncestorEntry = entry
                        }, onDelete: {
                            Task {
                                do {
                                    try await allowlistStore.removeAncestor(entry)
                                } catch {
                                    if !BiometricAuth.isUserCancellation(error) { authError = error }
                                }
                            }
                        })
                        .padding(.vertical, 4)
                    }
                }
            }
        }
        .listStyle(.inset)
    }
}

// MARK: - AllowlistEntryRow

private func suggestBaselineIssueURL(signingID: String) -> URL? {
    guard !signingID.isEmpty else { return nil }
    let title = "Add `\(signingID)` to baseline allowlist"
    let body = "**Signing ID**: `\(signingID)`\n\nThis Apple platform binary should be added to the baseline global allowlist."
    var components = URLComponents(string: "https://github.com/craigjbass/clearancekit/issues/new")
    components?.queryItems = [
        URLQueryItem(name: "title", value: title),
        URLQueryItem(name: "body", value: body),
    ]
    return components?.url
}

private enum AllowlistEntrySource { case baseline, managed, user }

private struct AllowlistEntryRow: View {
    let entry: AllowlistEntry
    let source: AllowlistEntrySource
    let isEditable: Bool
    let onEdit: () -> Void
    let onDelete: () -> Void

    private var issueURL: URL? {
        guard entry.platformBinary else { return nil }
        return suggestBaselineIssueURL(signingID: entry.signingID)
    }

    private var issueButtonLabel: String {
        source == .baseline ? "Report an issue" : "Suggest for baseline"
    }

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    identifierText
                    if entry.platformBinary {
                        badge("apple")
                    } else if !entry.teamID.isEmpty {
                        badge(entry.teamID)
                    }
                    if source == .baseline {
                        badge("baseline")
                    }
                }
                if !entry.signingID.isEmpty && !entry.processPath.isEmpty {
                    Text(entry.processPath)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer()
            if let url = issueURL {
                Button { NSWorkspace.shared.open(url) } label: {
                    Label(issueButtonLabel, systemImage: "ladybug")
                }
                .buttonStyle(.bordered)
                .controlSize(.mini)
            }
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
    }

    private var identifierText: some View {
        let text = entry.signingID.isEmpty ? entry.processPath : entry.signingID
        return Text(text)
            .font(.system(.body, design: .monospaced))
            .lineLimit(1)
    }

    private func badge(_ label: String) -> some View {
        Text(label)
            .font(.caption2)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(Color.secondary.opacity(0.15))
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }
}

// MARK: - AncestorAllowlistEntryRow

private struct AncestorAllowlistEntryRow: View {
    let entry: AncestorAllowlistEntry
    let isEditable: Bool
    let onEdit: () -> Void
    let onDelete: () -> Void

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Image(systemName: "arrow.up.right.square")
                        .foregroundStyle(.secondary)
                        .font(.caption)
                    identifierText
                    if entry.platformBinary {
                        badge("apple")
                    } else if !entry.teamID.isEmpty {
                        badge(entry.teamID)
                    }
                    badge("ancestor")
                }
                if !entry.signingID.isEmpty && !entry.processPath.isEmpty {
                    Text(entry.processPath)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
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
    }

    private var identifierText: some View {
        let text = entry.signingID.isEmpty ? entry.processPath : entry.signingID
        return Text(text)
            .font(.system(.body, design: .monospaced))
            .lineLimit(1)
    }

    private func badge(_ label: String) -> some View {
        Text(label)
            .font(.caption2)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(Color.secondary.opacity(0.15))
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }
}

// MARK: - AllowlistEntryEditView

struct AllowlistEntryEditView: View {
    enum MatchType: String, CaseIterable {
        case signingID = "Signing ID"
        case processPath = "Process Path"
    }

    @State private var matchType: MatchType
    @State private var value: String
    @State private var platformBinary: Bool
    @State private var teamID: String

    private let existing: AllowlistEntry?
    let onSave: (AllowlistEntry) -> Void
    let onCancel: () -> Void

    init(existing: AllowlistEntry? = nil, onSave: @escaping (AllowlistEntry) -> Void, onCancel: @escaping () -> Void) {
        self.existing = existing
        self.onSave = onSave
        self.onCancel = onCancel
        if let e = existing {
            _matchType      = State(initialValue: e.signingID.isEmpty ? .processPath : .signingID)
            _value          = State(initialValue: e.signingID.isEmpty ? e.processPath : e.signingID)
            _platformBinary = State(initialValue: e.platformBinary)
            _teamID         = State(initialValue: e.teamID)
        } else {
            _matchType      = State(initialValue: .signingID)
            _value          = State(initialValue: "")
            _platformBinary = State(initialValue: false)
            _teamID         = State(initialValue: "")
        }
    }

    private var isValid: Bool { !value.trimmingCharacters(in: .whitespaces).isEmpty }
    private var isEditing: Bool { existing != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(isEditing ? "Edit Allowlist Entry" : "Add Allowlist Entry")
                .font(.headline)
                .padding()

            Divider()

            Form {
                Picker("Match by", selection: $matchType) {
                    ForEach(MatchType.allCases, id: \.self) { type in
                        Text(type.rawValue).tag(type)
                    }
                }
                .pickerStyle(.segmented)

                TextField(
                    matchType == .signingID ? "com.example.app" : "/usr/bin/example",
                    text: $value
                )
                .font(.system(.body, design: .monospaced))

                Toggle("Platform binary (Apple)", isOn: $platformBinary)

                if !platformBinary {
                    TextField("Team ID (optional)", text: $teamID)
                        .font(.system(.body, design: .monospaced))
                }
            }
            .padding()

            Divider()

            HStack {
                Spacer()
                Button("Cancel") { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button(isEditing ? "Save" : "Add") {
                    let trimmed = value.trimmingCharacters(in: .whitespaces)
                    let entry = AllowlistEntry(
                        id:             existing?.id ?? UUID(),
                        signingID:      matchType == .signingID   ? trimmed : "",
                        processPath:    matchType == .processPath ? trimmed : "",
                        platformBinary: platformBinary,
                        teamID:         platformBinary ? "" : teamID.trimmingCharacters(in: .whitespaces)
                    )
                    onSave(entry)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!isValid)
            }
            .padding()
        }
        .frame(width: 420)
    }
}

// MARK: - AncestorAllowlistEntryEditView

struct AncestorAllowlistEntryEditView: View {
    enum MatchType: String, CaseIterable {
        case signingID = "Signing ID"
        case processPath = "Process Path"
    }

    @State private var matchType: MatchType
    @State private var value: String
    @State private var platformBinary: Bool
    @State private var teamID: String

    private let existing: AncestorAllowlistEntry?
    let onSave: (AncestorAllowlistEntry) -> Void
    let onCancel: () -> Void

    init(existing: AncestorAllowlistEntry? = nil, onSave: @escaping (AncestorAllowlistEntry) -> Void, onCancel: @escaping () -> Void) {
        self.existing = existing
        self.onSave = onSave
        self.onCancel = onCancel
        if let e = existing {
            _matchType      = State(initialValue: e.signingID.isEmpty ? .processPath : .signingID)
            _value          = State(initialValue: e.signingID.isEmpty ? e.processPath : e.signingID)
            _platformBinary = State(initialValue: e.platformBinary)
            _teamID         = State(initialValue: e.teamID)
        } else {
            _matchType      = State(initialValue: .signingID)
            _value          = State(initialValue: "")
            _platformBinary = State(initialValue: false)
            _teamID         = State(initialValue: "")
        }
    }

    private var isValid: Bool { !value.trimmingCharacters(in: .whitespaces).isEmpty }
    private var isEditing: Bool { existing != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(isEditing ? "Edit Ancestor Allowlist Entry" : "Add Ancestor Allowlist Entry")
                .font(.headline)
                .padding()

            Text("Allow access when any ancestor process in the calling chain matches this entry.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal)
                .padding(.bottom, 4)

            Divider()

            Form {
                Picker("Match ancestor by", selection: $matchType) {
                    ForEach(MatchType.allCases, id: \.self) { type in
                        Text(type.rawValue).tag(type)
                    }
                }
                .pickerStyle(.segmented)

                TextField(
                    matchType == .signingID ? "com.example.terminal" : "/usr/bin/bash",
                    text: $value
                )
                .font(.system(.body, design: .monospaced))

                Toggle("Platform binary (Apple)", isOn: $platformBinary)

                if !platformBinary {
                    TextField("Team ID (optional)", text: $teamID)
                        .font(.system(.body, design: .monospaced))
                }
            }
            .padding()

            Divider()

            HStack {
                Spacer()
                Button("Cancel") { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button(isEditing ? "Save" : "Add") {
                    let trimmed = value.trimmingCharacters(in: .whitespaces)
                    let entry = AncestorAllowlistEntry(
                        id:             existing?.id ?? UUID(),
                        signingID:      matchType == .signingID   ? trimmed : "",
                        processPath:    matchType == .processPath ? trimmed : "",
                        platformBinary: platformBinary,
                        teamID:         platformBinary ? "" : teamID.trimmingCharacters(in: .whitespaces)
                    )
                    onSave(entry)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!isValid)
            }
            .padding()
        }
        .frame(width: 420)
    }
}
