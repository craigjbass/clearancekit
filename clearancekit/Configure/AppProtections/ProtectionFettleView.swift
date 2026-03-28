//
//  ProtectionFettleView.swift
//  clearancekit
//

import SwiftUI
import AppKit

struct ProtectionFettleView: View {
    @State private var draft: ProtectionDraft
    let saveLabel: String
    let onSave: (ProtectionDraft) -> Void
    let onCancel: () -> Void

    @State private var showProcessPicker = false
    @State private var sigPickerForEntryID: UUID?

    init(initialDraft: ProtectionDraft, saveLabel: String, onSave: @escaping (ProtectionDraft) -> Void, onCancel: @escaping () -> Void) {
        self._draft = State(initialValue: initialDraft)
        self.saveLabel = saveLabel
        self.onSave = onSave
        self.onCancel = onCancel
    }

    var body: some View {
        VStack(spacing: 0) {
            headerView
            Divider()
            if draft.entries.isEmpty {
                emptyState
            } else {
                List {
                    ForEach($draft.entries) { $entry in
                        PathEntryRow(entry: $entry, onRemove: {
                            draft.entries.removeAll { $0.id == entry.id }
                        }, onPickProcess: {
                            sigPickerForEntryID = entry.id
                            showProcessPicker = true
                        })
                        .padding(.vertical, 4)
                    }
                }
                .listStyle(.inset)
            }
            Divider()
            footerButtons
        }
        .frame(width: 520, height: 560)
        .sheet(isPresented: $showProcessPicker) {
            if let entryID = sigPickerForEntryID {
                ProcessPickerView { process in
                    addSignature(from: process, to: entryID)
                    showProcessPicker = false
                    sigPickerForEntryID = nil
                } onCancel: {
                    showProcessPicker = false
                    sigPickerForEntryID = nil
                }
            }
        }
    }

    private var headerView: some View {
        HStack(spacing: 12) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: draft.appInfo.appPath))
                .resizable()
                .frame(width: 40, height: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text(draft.appInfo.appName)
                    .font(.headline)
                Text("Review the protected paths and which processes are allowed to access them.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding()
    }

    private var emptyState: some View {
        Text("No protected paths.")
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var footerButtons: some View {
        HStack {
            Button("Cancel", action: onCancel)
            Spacer()
            Button(saveLabel) { onSave(draft) }
                .disabled(draft.entries.isEmpty)
                .buttonStyle(.borderedProminent)
        }
        .padding()
    }

    private func addSignature(from process: RunningProcess, to entryID: UUID) {
        guard let index = draft.entries.firstIndex(where: { $0.id == entryID }) else { return }
        let effectiveTeamID = process.teamID.isEmpty ? appleTeamID : process.teamID
        let sig = ProcessSignature(teamID: effectiveTeamID, signingID: process.signingID.isEmpty ? "*" : process.signingID)
        guard !draft.entries[index].signatures.contains(sig) else { return }
        draft.entries[index].signatures.append(sig)
    }
}

// MARK: - PathEntryRow

private struct PathEntryRow: View {
    @Binding var entry: ProtectionDraft.PathEntry
    let onRemove: () -> Void
    let onPickProcess: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(entry.prefix)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(2)
                Spacer()
                Button(action: onRemove) {
                    Image(systemName: "trash")
                        .foregroundColor(.red)
                }
                .buttonStyle(.borderless)
            }

            VStack(alignment: .leading, spacing: 3) {
                ForEach(entry.signatures, id: \.self) { sig in
                    HStack {
                        Text(sig.description)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button {
                            entry.signatures.removeAll { $0 == sig }
                        } label: {
                            Image(systemName: "minus.circle.fill")
                                .foregroundColor(.red)
                        }
                        .buttonStyle(.borderless)
                    }
                }
                Button(action: onPickProcess) {
                    Label("Add allowed process", systemImage: "plus.circle")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
            }
        }
    }
}
