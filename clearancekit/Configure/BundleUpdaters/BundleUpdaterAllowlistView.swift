//
//  BundleUpdaterAllowlistView.swift
//  clearancekit
//

import SwiftUI

struct BundleUpdaterAllowlistView: View {
    @StateObject private var store = BundleUpdaterStore.shared
    @State private var isAddingEntry = false
    @State private var authError: Error? = nil

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            entryList
        }
        .navigationTitle("Bundle Updater Allowlist")
        .sheet(isPresented: $isAddingEntry) {
            BundleUpdaterEntryEditView { entry in
                Task {
                    do {
                        try await store.add(entry)
                        isAddingEntry = false
                    } catch {
                        if !BiometricAuth.isUserCancellation(error) { authError = error }
                    }
                }
            } onCancel: {
                isAddingEntry = false
            }
        }
        .alert("Authentication Failed", isPresented: Binding(
            get: { authError != nil },
            set: { if !$0 { authError = nil } }
        )) {
            Button("OK") { authError = nil }
        } message: {
            if let error = authError { Text(error.localizedDescription) }
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

    private var entryList: some View {
        List {
            ForEach(store.signatures) { entry in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(entry.signingID)
                            .font(.system(.body, design: .monospaced))
                            .lineLimit(1)
                        Text(entry.teamID)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Remove") {
                        Task {
                            do {
                                try await store.remove(entry)
                            } catch {
                                if !BiometricAuth.isUserCancellation(error) { authError = error }
                            }
                        }
                    }
                }
            }
        }
        .overlay {
            if store.signatures.isEmpty {
                ContentUnavailableView(
                    "No Bundle Updater Entries",
                    systemImage: "arrow.down.app",
                    description: Text("Add external updaters (e.g. Sparkle) that are allowed to write inside .app bundles.")
                )
            }
        }
    }
}

// MARK: - BundleUpdaterEntryEditView

struct BundleUpdaterEntryEditView: View {
    @State private var signingID: String
    @State private var platformBinary: Bool
    @State private var teamID: String

    let onSave: (BundleUpdaterSignature) -> Void
    let onCancel: () -> Void

    init(onSave: @escaping (BundleUpdaterSignature) -> Void, onCancel: @escaping () -> Void) {
        self.onSave = onSave
        self.onCancel = onCancel
        _signingID      = State(initialValue: "")
        _platformBinary = State(initialValue: false)
        _teamID         = State(initialValue: "")
    }

    private var isValid: Bool { !signingID.trimmingCharacters(in: .whitespaces).isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Add Bundle Updater Entry")
                .font(.headline)
                .padding()

            Divider()

            Form {
                TextField("com.example.sparkle", text: $signingID)
                    .font(.system(.body, design: .monospaced))

                Toggle("Platform binary (Apple)", isOn: $platformBinary)

                if !platformBinary {
                    TextField("Team ID", text: $teamID)
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
                    let entry = BundleUpdaterSignature(
                        teamID:    platformBinary ? "apple" : teamID.trimmingCharacters(in: .whitespaces),
                        signingID: signingID.trimmingCharacters(in: .whitespaces)
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
