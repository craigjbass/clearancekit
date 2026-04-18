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
            ProcessPickerView { process in
                let entry = BundleUpdaterSignature(teamID: process.teamID, signingID: process.signingID)
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

    @ViewBuilder
    private var entryList: some View {
        if store.signatures.isEmpty {
            ContentUnavailableView(
                "No Bundle Updater Entries",
                systemImage: "app.badge.checkmark",
                description: Text("Add external updaters (e.g. Sparkle) that are allowed to write inside .app bundles.")
            )
        } else {
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
        }
    }
}
