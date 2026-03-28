//
//  SantaExportView.swift
//  clearancekit
//

import SwiftUI
import AppKit

private enum SantaExportStep: Int, CaseIterable {
    case selectSources = 1
    case selectRules   = 2
    case review        = 3

    var title: String {
        switch self {
        case .selectSources: return "Sources"
        case .selectRules:   return "Rules"
        case .review:        return "Review"
        }
    }
}

struct SantaExportView: View {
    @StateObject private var policyStore = PolicyStore.shared
    @State private var step: SantaExportStep = .selectSources
    @State private var includeUserRules     = true
    @State private var includeManagedRules  = false
    @State private var includeBaselineRules = false
    @State private var selectedRuleIDs: Set<UUID> = []
    @State private var exportError: String?

    var body: some View {
        VStack(spacing: 0) {
            stepIndicator
            Divider()
            stepContent
            Divider()
            navigationFooter
        }
        .navigationTitle("Export as Santa")
    }

    // MARK: - Step indicator

    private var stepIndicator: some View {
        HStack(spacing: 0) {
            ForEach(SantaExportStep.allCases, id: \.rawValue) { s in
                HStack(spacing: 6) {
                    ZStack {
                        Circle()
                            .fill(s.rawValue <= step.rawValue ? Color.accentColor : Color.secondary.opacity(0.3))
                            .frame(width: 22, height: 22)
                        Text("\(s.rawValue)")
                            .font(.caption.bold())
                            .foregroundStyle(.white)
                    }
                    Text(s.title)
                        .font(.caption)
                        .foregroundStyle(s == step ? .primary : .secondary)
                }
                if s != .review {
                    Rectangle()
                        .fill(Color.secondary.opacity(0.25))
                        .frame(height: 1)
                        .frame(maxWidth: .infinity)
                        .padding(.horizontal, 8)
                }
            }
        }
        .padding()
        .background(Color(NSColor.windowBackgroundColor))
    }

    // MARK: - Step content

    @ViewBuilder
    private var stepContent: some View {
        switch step {
        case .selectSources: sourcesStep
        case .selectRules:   rulesStep
        case .review:        reviewStep
        }
    }

    // Step 1 — Choose which rule groups to include
    private var sourcesStep: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Choose which rule groups to include in the export.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            Divider()
            sourceRow(label: "User Rules", count: policyStore.userRules.count, isOn: $includeUserRules)
            Divider().padding(.leading)
            sourceRow(label: "Managed Profile Rules", count: policyStore.managedRules.count, isOn: $includeManagedRules)
            Divider().padding(.leading)
            sourceRow(label: "Baseline Rules", count: policyStore.baselineRules.count, isOn: $includeBaselineRules)
            Spacer()
        }
    }

    private func sourceRow(label: String, count: Int, isOn: Binding<Bool>) -> some View {
        Toggle(isOn: isOn) {
            HStack(spacing: 6) {
                Text(label)
                Text("\(count) rule\(count == 1 ? "" : "s")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .toggleStyle(.checkbox)
        .disabled(count == 0)
        .padding()
    }

    // Step 2 — Select individual rules
    @ViewBuilder
    private var rulesStep: some View {
        if candidateRules.isEmpty {
            VStack {
                Spacer()
                Text("No rules in the selected groups.")
                    .foregroundStyle(.secondary)
                Spacer()
            }
        } else {
            List {
                ForEach(candidateRules) { rule in
                    HStack(alignment: .top, spacing: 10) {
                        Toggle(isOn: ruleSelectionBinding(for: rule.id)) { EmptyView() }
                            .labelsHidden()
                        VStack(alignment: .leading, spacing: 4) {
                            Text(rule.protectedPathPrefix)
                                .font(.system(.body, design: .monospaced))
                                .fontWeight(.semibold)
                            if !rule.allowedSignatures.isEmpty {
                                Text(rule.allowedSignatures.map(\.description).joined(separator: ", "))
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                            if !rule.allowedProcessPaths.isEmpty {
                                Text(rule.allowedProcessPaths.joined(separator: ", "))
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            .listStyle(.inset)
        }
    }

    // Step 3 — Review & export
    private var reviewStep: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                Text("\(selectedRules.count) rule\(selectedRules.count == 1 ? "" : "s") ready to export")
                    .font(.headline)
            }
            .padding()

            Divider()

            Text("The export produces a Santa FileAccessPolicy mobileconfig that can be deployed via MDM.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .padding()

            if selectedRulesHaveAncestry {
                Divider()
                VStack(alignment: .leading, spacing: 8) {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                        Text("The following rules use ancestry matching. Santa's FileAccessPolicy has no equivalent — these criteria will be lost in the export.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(ancestryRules) { rule in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(rule.protectedPathPrefix)
                                .font(.system(.caption, design: .monospaced))
                                .fontWeight(.semibold)
                            ForEach(rule.allowedAncestorProcessPaths, id: \.self) { path in
                                Text(path)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                            ForEach(rule.allowedAncestorSignatures.map(\.description), id: \.self) { sig in
                                Text(sig)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(.leading, 30)
                    }
                }
                .padding()
            }

            if let error = exportError {
                Divider()
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.red)
                    Text(error)
                        .font(.callout)
                        .foregroundStyle(.red)
                }
                .padding()
            }

            Spacer()
        }
    }

    // MARK: - Navigation footer

    private var navigationFooter: some View {
        HStack {
            if step != .selectSources {
                Button("Back") { back() }
            }
            Spacer()
            if step == .review {
                Button("Export…") { export() }
                    .buttonStyle(.borderedProminent)
                    .disabled(selectedRules.isEmpty)
            } else {
                Button("Next") { advance() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canAdvance)
            }
        }
        .padding()
        .background(Color(NSColor.windowBackgroundColor))
    }

    // MARK: - Logic

    private var candidateRules: [FAARule] {
        var rules: [FAARule] = []
        if includeUserRules     { rules += policyStore.userRules }
        if includeManagedRules  { rules += policyStore.managedRules }
        if includeBaselineRules { rules += policyStore.baselineRules }
        return rules
    }

    private var selectedRules: [FAARule] {
        candidateRules.filter { selectedRuleIDs.contains($0.id) }
    }

    private var selectedRulesHaveAncestry: Bool {
        !ancestryRules.isEmpty
    }

    private var ancestryRules: [FAARule] {
        selectedRules.filter { $0.requiresAncestry }
    }

    private var canAdvance: Bool {
        switch step {
        case .selectSources: return !candidateRules.isEmpty
        case .selectRules:   return !selectedRuleIDs.isEmpty
        case .review:        return true
        }
    }

    private func advance() {
        switch step {
        case .selectSources:
            selectedRuleIDs = Set(candidateRules.map(\.id))
            step = .selectRules
        case .selectRules:
            step = .review
        case .review:
            break
        }
    }

    private func back() {
        switch step {
        case .selectSources: break
        case .selectRules:   step = .selectSources
        case .review:        step = .selectRules
        }
    }

    private func ruleSelectionBinding(for ruleID: UUID) -> Binding<Bool> {
        Binding(
            get: { selectedRuleIDs.contains(ruleID) },
            set: { checked in
                if checked { selectedRuleIDs.insert(ruleID) }
                else { selectedRuleIDs.remove(ruleID) }
            }
        )
    }

    private func export() {
        exportError = nil
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "clearancekit-santa-faa.mobileconfig"
        panel.title = "Export as Santa mobileconfig"
        panel.message = "Choose where to save the Santa FileAccessPolicy mobileconfig."

        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            let result = try SantaMobileconfigExporter.export(rules: selectedRules)
            try result.data.write(to: url)
        } catch {
            exportError = "Export failed: \(error.localizedDescription)"
        }
    }
}
