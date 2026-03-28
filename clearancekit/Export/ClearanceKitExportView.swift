//
//  ClearanceKitExportView.swift
//  clearancekit
//

import SwiftUI
import AppKit

private enum ClearanceKitExportStep: Int, CaseIterable {
    case policy      = 1  // FAA rules + App Protections
    case enforcement = 2  // Jail rules + Allowlist
    case review      = 3  // Summary + Export

    var title: String {
        switch self {
        case .policy:      return "Policy"
        case .enforcement: return "Enforcement"
        case .review:      return "Review"
        }
    }
}

struct ClearanceKitExportView: View {
    @StateObject private var policyStore      = PolicyStore.shared
    @StateObject private var protectionStore  = AppProtectionStore.shared
    @StateObject private var jailStore        = JailStore.shared
    @StateObject private var allowlistStore   = AllowlistStore.shared

    // Policy step toggles
    @State private var includeUserRules          = true
    @State private var includeManagedRules        = false
    @State private var includeBaselineRules       = false
    @State private var includeUserProtections     = true
    @State private var includeManagedProtections  = false

    // Enforcement step toggles
    @State private var includeUserJailRules      = true
    @State private var includeManagedJailRules   = false
    @State private var includeUserAllowlist      = true

    @State private var step: ClearanceKitExportStep = .policy
    @State private var exportError: String?

    var body: some View {
        VStack(spacing: 0) {
            stepIndicator
            Divider()
            stepContent
            Divider()
            navigationFooter
        }
        .navigationTitle("Export as ClearanceKit")
    }

    // MARK: - Step indicator

    private var stepIndicator: some View {
        HStack(spacing: 0) {
            ForEach(ClearanceKitExportStep.allCases, id: \.rawValue) { s in
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
        case .policy:      policyStep
        case .enforcement: enforcementStep
        case .review:      reviewStep
        }
    }

    // Step 1 — Policy rules and App Protections
    private var policyStep: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionHeader("Policy Rules")
            sourceRow(label: "User Rules",            count: policyStore.userRules.count,           isOn: $includeUserRules)
            Divider().padding(.leading)
            sourceRow(label: "Managed Profile Rules", count: policyStore.managedRules.count,        isOn: $includeManagedRules)
            Divider().padding(.leading)
            sourceRow(label: "Baseline Rules",        count: policyStore.baselineRules.count,       isOn: $includeBaselineRules)
            sectionHeader("App Protections")
            sourceRow(label: "User Protections",      count: protectionStore.protections.count,     isOn: $includeUserProtections)
            Divider().padding(.leading)
            sourceRow(label: "Managed Protections",   count: protectionStore.managedProtections.count, isOn: $includeManagedProtections)
            Spacer()
        }
    }

    // Step 2 — Jail rules and Allowlist
    private var enforcementStep: some View {
        VStack(alignment: .leading, spacing: 0) {
            sectionHeader("Jail Rules")
            sourceRow(label: "User Jail Rules",    count: jailStore.userRules.count,    isOn: $includeUserJailRules)
            Divider().padding(.leading)
            sourceRow(label: "Managed Jail Rules", count: jailStore.managedRules.count, isOn: $includeManagedJailRules)
            sectionHeader("Allowlist")
            sourceRow(label: "User Allowlist Entries", count: allowlistStore.userEntries.count, isOn: $includeUserAllowlist)
            Spacer()
        }
    }

    // Step 3 — Summary and export
    private var reviewStep: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 6) {
                    Image(systemName: totalItems > 0 ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                        .foregroundStyle(totalItems > 0 ? .green : .orange)
                    Text(totalItems > 0
                         ? "\(totalItems) item\(totalItems == 1 ? "" : "s") will be exported"
                         : "Nothing selected — choose at least one source.")
                        .font(.headline)
                }

                reviewRow(label: "Policy Rules",    count: exportedRules.count,           icon: "shield")
                reviewRow(label: "App Protections", count: exportedProtections.count,      icon: "lock.app.dashed")
                reviewRow(label: "Jail Rules",       count: exportedJailRules.count,       icon: "lock.rectangle.on.rectangle")
                reviewRow(label: "Allowlist",        count: exportedAllowlistEntries.count, icon: "checkmark.shield")
            }
            .padding()

            if detachedProtectionCount > 0 {
                Divider()
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("\(detachedProtectionCount) App Protection\(detachedProtectionCount == 1 ? "" : "s") reference rule IDs not included in the exported policy. Add the corresponding rule groups on the Policy step or the protections will reference missing rules.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
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

    // MARK: - Reusable row builders

    private func sectionHeader(_ title: String) -> some View {
        Text(title)
            .font(.headline)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal)
            .padding(.top, 12)
            .padding(.bottom, 4)
    }

    private func sourceRow(label: String, count: Int, isOn: Binding<Bool>) -> some View {
        Toggle(isOn: isOn) {
            HStack(spacing: 6) {
                Text(label)
                Text("\(count) \(count == 1 ? "entry" : "entries")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .toggleStyle(.checkbox)
        .disabled(count == 0)
        .padding()
    }

    private func reviewRow(label: String, count: Int, icon: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .frame(width: 18)
                .foregroundStyle(count > 0 ? .primary : .tertiary)
            Text(label)
                .foregroundStyle(count > 0 ? .primary : .tertiary)
            Spacer()
            Text("\(count)")
                .foregroundStyle(count > 0 ? .primary : .tertiary)
                .monospacedDigit()
        }
        .font(.callout)
    }

    // MARK: - Navigation footer

    private var navigationFooter: some View {
        HStack {
            if step != .policy {
                Button("Back") { back() }
            }
            Spacer()
            if step == .review {
                Button("Export…") { export() }
                    .buttonStyle(.borderedProminent)
                    .disabled(totalItems == 0)
            } else {
                Button("Next") { advance() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .background(Color(NSColor.windowBackgroundColor))
    }

    // MARK: - Derived export sets

    private var exportedRules: [FAARule] {
        var rules: [FAARule] = []
        if includeUserRules     { rules += policyStore.userRules }
        if includeManagedRules  { rules += policyStore.managedRules }
        if includeBaselineRules { rules += policyStore.baselineRules }
        return rules
    }

    private var exportedProtections: [AppProtection] {
        var protections: [AppProtection] = []
        if includeUserProtections    { protections += protectionStore.protections }
        if includeManagedProtections { protections += protectionStore.managedProtections }
        return protections
    }

    private var exportedJailRules: [JailRule] {
        var rules: [JailRule] = []
        if includeUserJailRules    { rules += jailStore.userRules }
        if includeManagedJailRules { rules += jailStore.managedRules }
        return rules
    }

    private var exportedAllowlistEntries: [AllowlistEntry] {
        includeUserAllowlist ? allowlistStore.userEntries : []
    }

    private var totalItems: Int {
        exportedRules.count + exportedProtections.count + exportedJailRules.count + exportedAllowlistEntries.count
    }

    /// Number of exported AppProtections that reference at least one ruleID not present in exportedRules.
    private var detachedProtectionCount: Int {
        let exportedRuleIDs = Set(exportedRules.map(\.id))
        return exportedProtections.filter { protection in
            protection.ruleIDs.contains { !exportedRuleIDs.contains($0) }
        }.count
    }

    // MARK: - Navigation

    private func advance() {
        switch step {
        case .policy:      step = .enforcement
        case .enforcement: step = .review
        case .review:      break
        }
    }

    private func back() {
        switch step {
        case .policy:      break
        case .enforcement: step = .policy
        case .review:      step = .enforcement
        }
    }

    // MARK: - Export

    private func export() {
        exportError = nil
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "clearancekit-managed-policy.mobileconfig"
        panel.title = "Export ClearanceKit Policy"
        panel.message = "Choose where to save the ClearanceKit managed policy mobileconfig."

        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            let data = try ClearanceKitMobileconfigExporter.export(
                rules: exportedRules,
                protections: exportedProtections,
                jailRules: exportedJailRules,
                allowlistEntries: exportedAllowlistEntries
            )
            try data.write(to: url)
        } catch {
            exportError = "Export failed: \(error.localizedDescription)"
        }
    }
}
