//
//  JailView.swift
//  clearancekit
//

import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct JailView: View {
    @StateObject private var store = JailStore.shared

    @State private var editingRule: JailRule?
    @State private var showAddSheet = false
    @State private var showImportExport = false

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
                    showImportExport = true
                } label: {
                    Label("Import / Export", systemImage: "arrow.up.arrow.down")
                }
                .popover(isPresented: $showImportExport) {
                    JailImportExportPopover()
                }
            }
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
    @State private var signatureText: String
    @State private var allowedPrefixes: [String]
    @State private var showProcessPicker = false

    private let existingID: UUID?

    init(existingRule: JailRule? = nil, onSave: @escaping (JailRule) -> Void) {
        self.onSave = onSave
        self.existingID = existingRule?.id
        _name = State(initialValue: existingRule?.name ?? "")
        _signatureText = State(initialValue: existingRule?.jailedSignature.description ?? "")
        _allowedPrefixes = State(initialValue: existingRule?.allowedPathPrefixes ?? [])
    }

    private var parsedSignature: ProcessSignature? {
        guard let colonIndex = signatureText.firstIndex(of: ":") else { return nil }
        let team = String(signatureText[signatureText.startIndex..<colonIndex])
        let signing = String(signatureText[signatureText.index(after: colonIndex)...])
        guard !signing.isEmpty else { return nil }
        // Normalise empty team ID to appleTeamID so the rule matches correctly,
        // consistent with how process events are resolved before matching.
        let effectiveTeam = team.isEmpty ? appleTeamID : team
        return ProcessSignature(teamID: effectiveTeam, signingID: signing)
    }

    private var isValid: Bool {
        !name.isEmpty && parsedSignature != nil
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section("Rule") {
                    TextField("Name", text: $name)
                }
                Section {
                    HStack {
                        TextField("teamID:signingID", text: $signatureText)
                            .font(.system(.body, design: .monospaced))
                        Button("Pick...") { showProcessPicker = true }
                    }
                } header: {
                    Text("Jailed Process")
                } footer: {
                    Text("Wildcards (*) are not supported for jail rules.")
                        .foregroundStyle(.secondary)
                }
                Section {
                    ForEach(allowedPrefixes.indices, id: \.self) { index in
                        HStack {
                            TextField("e.g. /var/log/**", text: $allowedPrefixes[index])
                                .font(.body.monospaced())
                            Button {
                                allowedPrefixes.remove(at: index)
                            } label: {
                                Image(systemName: "minus.circle.fill")
                                    .foregroundStyle(.red)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    Button {
                        allowedPrefixes.append("")
                    } label: {
                        Label("Add Path", systemImage: "plus.circle.fill")
                    }
                } header: {
                    Text("Allowed Paths")
                } footer: {
                    Text(
                        """
                        * — matches exactly one path component.
                        ** — once reached, matches everything (including the path up to that point).
                        *** — character wildcard within a single component.

                        /var/log          exact path only, no children
                        /var/log/*        direct children only, not /var/log itself
                        /var/log/**       /var/log and all descendants at any depth
                        /dev/ttys***      /dev/ttys001, /dev/ttysA, …
                        """
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    guard let sig = parsedSignature else { return }
                    let rule = JailRule(
                        id: existingID ?? UUID(),
                        name: name,
                        jailedSignature: sig,
                        allowedPathPrefixes: allowedPrefixes
                    )
                    onSave(rule)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!isValid)
            }
            .padding()
        }
        .frame(minWidth: 500, minHeight: 400)
        .sheet(isPresented: $showProcessPicker) {
            ProcessPickerView { process in
                let effectiveTeamID = process.teamID.isEmpty ? appleTeamID : process.teamID
                signatureText = "\(effectiveTeamID):\(process.signingID)"
                if name.isEmpty { name = process.name }
                showProcessPicker = false
            } onCancel: {
                showProcessPicker = false
            }
        }
    }
}

// MARK: - JailImportExportPopover

private struct JailImportExportPopover: View {
    @StateObject private var store = JailStore.shared
    @State private var selectedIDs: Set<UUID> = []
    @State private var importStatusMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            exportSection
            Divider()
            importSection
        }
        .frame(width: 380)
        .onAppear {
            selectedIDs = Set(store.userRules.map(\.id))
        }
    }

    private var exportSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Export").font(.headline)
            if store.userRules.isEmpty {
                Text("No user jail rules to export.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                List(store.userRules) { rule in
                    Toggle(isOn: Binding(
                        get: { selectedIDs.contains(rule.id) },
                        set: { if $0 { selectedIDs.insert(rule.id) } else { selectedIDs.remove(rule.id) } }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(rule.name)
                            Text(rule.jailedSignature.description)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .listStyle(.plain)
                .frame(minHeight: 60, maxHeight: 220)

                HStack {
                    Button("Select All") { selectedIDs = Set(store.userRules.map(\.id)) }
                        .buttonStyle(.borderless)
                    Button("Deselect All") { selectedIDs = [] }
                        .buttonStyle(.borderless)
                    Spacer()
                    Button("Export Selected") { exportSelected() }
                        .disabled(selectedIDs.isEmpty)
                }
            }
        }
        .padding()
    }

    private var importSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Import").font(.headline)
            HStack {
                Button("Import from File…") { importFromFile() }
                if let msg = importStatusMessage {
                    Text(msg)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding()
    }

    private func exportSelected() {
        let rulesToExport = store.userRules.filter { selectedIDs.contains($0.id) }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(rulesToExport) else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "jail-rules.json"
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            try? data.write(to: url)
        }
    }

    private func importFromFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            guard let data = try? Data(contentsOf: url),
                  let rules = try? JSONDecoder().decode([JailRule].self, from: data) else {
                importStatusMessage = "Invalid file"
                return
            }
            Task { @MainActor in
                do {
                    let count = try await store.importRules(rules)
                    importStatusMessage = count == 0
                        ? "No new rules (all already present)"
                        : "\(count) rule(s) imported"
                } catch {
                    importStatusMessage = "Import cancelled"
                }
            }
        }
    }
}
