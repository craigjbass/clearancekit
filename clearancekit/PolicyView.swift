//
//  PolicyView.swift
//  clearancekit
//

import SwiftUI

struct PolicyView: View {
    @StateObject private var policyStore = PolicyStore.shared

    var body: some View {
        if policyStore.rules.isEmpty {
            VStack {
                Spacer()
                Text("No rules configured")
                    .foregroundStyle(.secondary)
                Spacer()
            }
        } else {
            List(policyStore.rules) { rule in
                RuleRow(rule: rule)
                    .padding(.vertical, 4)
            }
            .listStyle(.inset)
        }
    }
}

// MARK: - RuleRow

private struct RuleRow: View {
    let rule: FAARule

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(rule.protectedPathPrefix)
                .font(.system(.body, design: .monospaced))
                .fontWeight(.semibold)

            criterionGroup("Allowed process paths", rule.allowedProcessPaths)
            criterionGroup("Allowed team IDs", rule.allowedTeamIDs)
            criterionGroup("Allowed signing IDs", rule.allowedSigningIDs)
            criterionGroup("Allowed ancestor paths", rule.allowedAncestorProcessPaths)
            criterionGroup("Allowed ancestor team IDs", rule.allowedAncestorTeamIDs)
            criterionGroup("Allowed ancestor signing IDs", rule.allowedAncestorSigningIDs)
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
