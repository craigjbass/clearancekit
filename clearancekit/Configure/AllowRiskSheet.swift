//
//  AllowRiskSheet.swift
//  clearancekit
//

import SwiftUI

struct AllowRiskSheet: View {
    let riskyLabels: [String]
    let risks: [AllowRisk]
    let onAllowAnyway: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(risks, id: \.self) { risk in
                Label(AllowRiskCopy.title(for: risk), systemImage: "exclamationmark.triangle.fill")
                    .font(.headline)
                    .foregroundStyle(.orange)
                Text(LocalizedStringKey(AllowRiskCopy.body(for: risk)))
                    .fixedSize(horizontal: false, vertical: true)
            }
            VStack(alignment: .leading, spacing: 2) {
                ForEach(riskyLabels, id: \.self) { label in
                    Text(label)
                        .font(.system(.caption, design: .monospaced))
                }
            }
            HStack {
                Spacer()
                Button(AllowRiskCopy.allowAnyway, role: .destructive, action: onAllowAnyway)
                Button(AllowRiskCopy.cancel, action: onCancel)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .frame(width: 440)
    }
}

struct AllowRiskBadge: View {
    let risk: AllowRisk

    var body: some View {
        Label {
            Text(LocalizedStringKey(AllowRiskCopy.body(for: risk)))
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill")
        }
        .font(.caption)
        .foregroundStyle(.orange)
    }
}

extension View {
    func allowRiskConfirmation(_ gate: AllowRiskGate) -> some View {
        sheet(item: Binding(
            get: { gate.pendingChange },
            set: { if $0 == nil { gate.cancel() } }
        )) { change in
            AllowRiskSheet(
                riskyLabels: change.riskyLabels,
                risks: change.risks,
                onAllowAnyway: { gate.allowAnyway() },
                onCancel: { gate.cancel() }
            )
        }
    }
}
