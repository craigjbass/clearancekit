//
//  SpotlightIndexerRiskSheet.swift
//  clearancekit
//

import SwiftUI

struct SpotlightIndexerRiskSheet: View {
    let riskyLabels: [String]
    let onAllowAnyway: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(SpotlightIndexerRiskCopy.title, systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.orange)
            Text(LocalizedStringKey(SpotlightIndexerRiskCopy.body))
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 2) {
                ForEach(riskyLabels, id: \.self) { label in
                    Text(label)
                        .font(.system(.caption, design: .monospaced))
                }
            }
            HStack {
                Spacer()
                Button(SpotlightIndexerRiskCopy.allowAnyway, role: .destructive, action: onAllowAnyway)
                Button(SpotlightIndexerRiskCopy.cancel, action: onCancel)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .frame(width: 440)
    }
}

struct SpotlightIndexerRiskBadge: View {
    var body: some View {
        Label {
            Text(LocalizedStringKey(SpotlightIndexerRiskCopy.body))
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill")
        }
        .font(.caption)
        .foregroundStyle(.orange)
    }
}

extension View {
    func spotlightIndexerRiskConfirmation(_ gate: SpotlightRiskGate) -> some View {
        sheet(item: Binding(
            get: { gate.pendingChange },
            set: { if $0 == nil { gate.cancel() } }
        )) { change in
            SpotlightIndexerRiskSheet(
                riskyLabels: change.riskyLabels,
                onAllowAnyway: { gate.allowAnyway() },
                onCancel: { gate.cancel() }
            )
        }
    }
}
