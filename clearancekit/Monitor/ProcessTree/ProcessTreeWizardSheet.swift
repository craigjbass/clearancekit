//
//  ProcessTreeWizardSheet.swift
//  clearancekit
//

import AppKit
import SwiftUI

struct ProcessTreeWizardSheet: View {
    let process: RunningProcessInfo
    @Environment(\.dismiss) private var dismiss

    @State private var destination: WizardDestination?

    private enum WizardDestination {
        case policyRule, jailRule, appProtection
    }

    var body: some View {
        switch destination {
        case .none:
            typePicker
        case .policyRule:
            RuleEditView(prefilledFrom: process) { rule in
                Task { try? await PolicyStore.shared.add(rule) }
                dismiss()
            } onCancel: {
                destination = nil
            }
        case .jailRule:
            JailRuleEditView(prefilledFrom: process, onSave: { rule in
                Task { try? await JailStore.shared.add(rule) }
                dismiss()
            }, onCancel: {
                destination = nil
            })
        case .appProtection:
            ProtectionFettleView(
                initialDraft: ProtectionDraft(prefilledFrom: process),
                saveLabel: "Create Protection"
            ) { draft in
                Task { try? await AppProtectionStore.shared.create(from: draft) }
                dismiss()
            } onCancel: {
                destination = nil
            }
        }
    }

    private var typePicker: some View {
        VStack(spacing: 0) {
            processHeader
            Divider()
            typeCards
            Divider()
            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
            }
            .padding()
        }
        .frame(width: 560)
    }

    private var processHeader: some View {
        HStack(spacing: 12) {
            Image(nsImage: {
                let img = NSWorkspace.shared.icon(forFile: process.path)
                img.size = NSSize(width: 40, height: 40)
                return img
            }())
            VStack(alignment: .leading, spacing: 2) {
                Text(URL(fileURLWithPath: process.path).lastPathComponent)
                    .font(.headline)
                Text(process.path)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if !process.signingID.isEmpty {
                    Text("\(process.teamID.isEmpty ? "Apple" : process.teamID) · \(process.signingID)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
        }
        .padding()
    }

    private var typeCards: some View {
        HStack(spacing: 12) {
            WizardTypeCard(
                systemImage: "doc.badge.plus",
                title: "Policy Rule",
                description: "Control which processes may read or write specific file paths."
            ) { destination = .policyRule }

            WizardTypeCard(
                systemImage: "lock.rectangle.on.rectangle",
                title: "Jail Rule",
                description: "Confine this process to a defined set of allowed paths."
            ) { destination = .jailRule }

            WizardTypeCard(
                systemImage: "shield.lefthalf.filled",
                title: "App Protection",
                description: "Protect this app's data directories from other processes."
            ) { destination = .appProtection }
        }
        .padding()
    }
}

// MARK: - WizardTypeCard

private struct WizardTypeCard: View {
    let systemImage: String
    let title: String
    let description: String
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: 10) {
                Image(systemName: systemImage)
                    .font(.system(size: 28))
                    .foregroundStyle(Color.accentColor)
                Text(title)
                    .font(.headline)
                Text(description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(16)
            .frame(maxWidth: .infinity, minHeight: 130)
            .background(isHovered ? Color.accentColor.opacity(0.08) : Color.secondary.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .strokeBorder(isHovered ? Color.accentColor.opacity(0.5) : Color.clear, lineWidth: 1.5)
            )
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
    }
}
