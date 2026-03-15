//
//  AllowlistView.swift
//  clearancekit
//

import SwiftUI

struct AllowlistView: View {
    @StateObject private var allowlistStore = AllowlistStore.shared
    @State private var isAddingEntry = false

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            entryList
        }
        .sheet(isPresented: $isAddingEntry) {
            AllowlistEntryAddView { entry in
                Task {
                    do {
                        try await allowlistStore.add(entry)
                        isAddingEntry = false
                    } catch {}
                }
            } onCancel: {
                isAddingEntry = false
            }
        }
    }

    private var toolbar: some View {
        HStack {
            Spacer()
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
                        AllowlistEntryRow(entry: entry, isEditable: false) { }
                            .padding(.vertical, 4)
                    }
                }
            }
            if !allowlistStore.managedEntries.isEmpty {
                Section("Managed Profile Entries") {
                    ForEach(allowlistStore.managedEntries) { entry in
                        AllowlistEntryRow(entry: entry, isEditable: false) { }
                            .padding(.vertical, 4)
                    }
                }
            }
            if !allowlistStore.userEntries.isEmpty {
                Section("User Entries") {
                    ForEach(allowlistStore.userEntries) { entry in
                        AllowlistEntryRow(entry: entry, isEditable: true) {
                            Task { try? await allowlistStore.remove(entry) }
                        }
                        .padding(.vertical, 4)
                    }
                }
            }
        }
        .listStyle(.inset)
    }
}

// MARK: - AllowlistEntryRow

private struct AllowlistEntryRow: View {
    let entry: AllowlistEntry
    let isEditable: Bool
    let onDelete: () -> Void

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
                    if !isEditable {
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
            if isEditable {
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

// MARK: - AllowlistEntryAddView

struct AllowlistEntryAddView: View {
    enum MatchType: String, CaseIterable {
        case signingID = "Signing ID"
        case processPath = "Process Path"
    }

    @State private var matchType: MatchType = .signingID
    @State private var value = ""
    @State private var platformBinary = false
    @State private var teamID = ""

    let onAdd: (AllowlistEntry) -> Void
    let onCancel: () -> Void

    private var isValid: Bool { !value.trimmingCharacters(in: .whitespaces).isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Add Allowlist Entry")
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
                Button("Add") {
                    let trimmed = value.trimmingCharacters(in: .whitespaces)
                    let entry = AllowlistEntry(
                        signingID:    matchType == .signingID   ? trimmed : "",
                        processPath:  matchType == .processPath ? trimmed : "",
                        platformBinary: platformBinary,
                        teamID: platformBinary ? "" : teamID.trimmingCharacters(in: .whitespaces)
                    )
                    onAdd(entry)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!isValid)
            }
            .padding()
        }
        .frame(width: 420)
    }
}
