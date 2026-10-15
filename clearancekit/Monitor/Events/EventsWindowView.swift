//
//  EventsWindowView.swift
//  clearancekit
//
//  Created by Craig J. Bass on 03/03/2026.
//

import SwiftUI

struct EventsWindowView: View {
    @StateObject private var xpcClient = XPCClient.shared
    @ObservedObject private var nav = NavigationState.shared
    @State private var filter: EventFilter = .deny
    @State private var defaultAllowVisibility: DefaultAllowVisibility = .hidden

    private static let maxDisplayedEvents = 1250

    private var filteredEvents: [FolderOpenEvent] {
        let listFilter = EventListFilter(
            decision: filter,
            defaultAllows: defaultAllowVisibility,
            quietList: nav.quietListVisibility
        )
        return Array(listFilter.apply(to: xpcClient.events).prefix(Self.maxDisplayedEvents))
    }

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            eventList
        }
        .onAppear {
            xpcClient.beginAllowEventStream()
            if nav.quietListVisibility == .shown {
                xpcClient.beginQuietEventStream()
            }
        }
        .onDisappear {
            xpcClient.endAllowEventStream()
            if nav.quietListVisibility == .shown {
                xpcClient.endQuietEventStream()
            }
        }
    }

    private var toolbar: some View {
        HStack {
            Picker("Filter", selection: $filter) {
                ForEach(EventFilter.allCases, id: \.self) { f in
                    Text(f.rawValue).tag(f)
                }
            }
            .pickerStyle(.segmented)
            .fixedSize()

            Toggle("Show default allows", isOn: defaultAllowsToggle)
                .toggleStyle(.checkbox)

            Toggle("Show quiet list processes", isOn: quietListToggle)
                .toggleStyle(.checkbox)

            Spacer()

            Button("Load History") {
                xpcClient.fetchHistoricEvents()
            }

            Button("Clear") {
                xpcClient.clearEvents()
            }
        }
        .padding()
        .background(Color(NSColor.windowBackgroundColor))
    }

    private var defaultAllowsToggle: Binding<Bool> {
        Binding(
            get: { defaultAllowVisibility == .shown },
            set: { defaultAllowVisibility = $0 ? .shown : .hidden }
        )
    }

    private var quietListToggle: Binding<Bool> {
        Binding(
            get: { nav.quietListVisibility == .shown },
            set: { isOn in
                nav.quietListVisibility = isOn ? .shown : .hidden
                if isOn {
                    xpcClient.beginQuietEventStream()
                    return
                }
                xpcClient.endQuietEventStream()
            }
        )
    }

    private var eventList: some View {
        Group {
            if filteredEvents.isEmpty {
                VStack {
                    Spacer()
                    Text("No events")
                        .foregroundColor(.secondary)
                    if filter != .all {
                        Text("No \(filter.rawValue.lowercased()) events recorded")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                }
            } else {
                ScrollViewReader { proxy in
                    List(filteredEvents, id: \.eventID) { event in
                        EventRow(event: event, isHighlighted: nav.highlightedEventID == event.eventID)
                    }
                    .listStyle(.inset)
                    .onChange(of: nav.highlightedEventID) { _, eventID in
                        guard let eventID else { return }
                        Task { @MainActor in
                            filter = .deny
                            withAnimation { proxy.scrollTo(eventID, anchor: .center) }
                            try? await Task.sleep(for: .seconds(5))
                            nav.highlightedEventID = nil
                        }
                    }
                }
            }
        }
    }
}

// MARK: - EventRow

struct EventRow: View {
    let event: FolderOpenEvent
    let isHighlighted: Bool
    @State private var allowedItems: Set<String> = []
    @State private var isExpanded = false
    @StateObject private var riskGate = AllowRiskGate()

    private static let baselineRuleIDs: Set<UUID> = Set(faaPolicy.map(\.id))

    private var isBaselineEvent: Bool {
        guard let ruleID = event.matchedRuleID else { return false }
        return Self.baselineRuleIDs.contains(ruleID)
    }

    private var displayPath: String {
        guard let secondaryPath = event.secondaryPath else { return event.path }
        return "\(event.path) \u{2192} \(secondaryPath)"
    }

    private var isManagedEvent: Bool {
        guard let ruleID = event.matchedRuleID else { return false }
        return PolicyStore.shared.managedRules.contains { $0.id == ruleID }
    }

    /// True for any event matched by a read-only policy tier (baseline or managed).
    private var isReadOnlyEvent: Bool { isBaselineEvent || isManagedEvent }

    private var canAllowDeny: Bool { !event.accessAllowed && !isReadOnlyEvent }

    private var canQuietNotifications: Bool {
        guard !event.accessAllowed else { return false }
        return event.notificationPolicy == .notify
    }

    private var processTarget: EventProcessTarget { EventProcessTarget(event: event) }

    private var suggestBaselineIssueURL: URL? {
        let target = processTarget
        guard !event.accessAllowed, target.teamID.isEmpty, !target.signingID.isEmpty else { return nil }
        let title = "Add `\(target.signingID)` to baseline allowlist"
        let body = "**Signing ID**: `\(target.signingID)`\n**Process path**: `\(target.processPath)`\n\nThis Apple platform binary is triggering deny events and should be added to the baseline global allowlist."
        var components = URLComponents(string: "https://github.com/craigjbass/clearancekit/issues/new")
        components?.queryItems = [
            URLQueryItem(name: "title", value: title),
            URLQueryItem(name: "body", value: body),
        ]
        return components?.url
    }

    private var isJailedUserDeny: Bool {
        guard let ruleID = event.jailedRuleID, !event.accessAllowed else { return false }
        return JailStore.shared.userRules.contains { $0.id == ruleID }
    }

    private var matchedRule: FAARule? {
        guard let ruleID = event.matchedRuleID else { return nil }
        return PolicyStore.shared.userRules.first { $0.id == ruleID }
            ?? PolicyStore.shared.managedRules.first { $0.id == ruleID }
            ?? faaPolicy.first { $0.id == ruleID }
    }

    private var matchedSource: (name: String, icon: NSImage)? {
        guard let rule = matchedRule else { return nil }
        let allProtections = AppProtectionStore.shared.protections + AppProtectionStore.shared.managedProtections
        if let protection = allProtections.first(where: { $0.ruleIDs.contains(rule.id) }) {
            return (protection.appName, protection.icon)
        }
        if let preset = builtInPresets.first(where: { $0.rules.contains { $0.id == rule.id } }) {
            return (preset.appName, preset.icon)
        }
        return nil
    }

    private var formattedTime: String {
        let formatter = DateFormatter()
        formatter.timeStyle = .medium
        if Calendar.current.isDateInToday(event.timestamp) {
            formatter.dateStyle = .none
        } else {
            formatter.dateStyle = .short
        }
        return formatter.string(from: event.timestamp)
    }

    var body: some View {
        let row = isReadOnlyEvent ? AnyView(compactRow) : AnyView(fullRow)
        row.overlay(
            RoundedRectangle(cornerRadius: 4)
                .stroke(Color.orange, lineWidth: isHighlighted ? 2 : 0)
                .animation(.easeOut(duration: 0.3), value: isHighlighted)
        )
        .allowRiskConfirmation(riskGate)
    }

    // MARK: - Compact read-only row (baseline + managed, expandable)

    private var compactRow: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { isExpanded.toggle() }
            } label: {
                HStack {
                    Image(systemName: event.accessAllowed ? "checkmark.shield.fill" : "xmark.shield.fill")
                        .foregroundColor(event.accessAllowed ? .green : .red)
                    Text(displayPath)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)
                    if event.operation != "open" {
                        operationBadge
                    }
                    jailBadge
                    Text(isBaselineEvent ? "baseline" : "managed")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                    Spacer()
                    Text(formattedTime)
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
            .buttonStyle(.plain)

            if isExpanded {
                VStack(alignment: .leading, spacing: 4) {
                    processSection
                    if !event.decisionReason.isEmpty {
                        Text(event.decisionReason)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if !event.ancestors.isEmpty {
                        ancestorsSection
                    }
                }
                .padding(.top, 4)
            }
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 4)
        .background(
            RoundedRectangle(cornerRadius: 4)
                .fill(event.accessAllowed ? Color.green.opacity(0.05) : Color.red.opacity(0.1))
        )
    }

    // MARK: - Full row (user rules)

    private var fullRow: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: event.accessAllowed ? "checkmark.shield.fill" : "xmark.shield.fill")
                    .foregroundColor(event.accessAllowed ? .green : .red)
                if isJailedUserDeny, let ruleID = event.jailedRuleID {
                    allowButton(label: event.path, itemKey: "jail-path", risk: .noKnownRisk) {
                        try await JailStore.shared.allowPath(event.path, inRule: ruleID)
                    }
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                } else {
                    Text(displayPath)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                }
                if event.operation != "open" {
                    operationBadge
                }
                jailBadge
                Spacer()
                Text(event.accessAllowed ? "Allowed" : "Denied")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(event.accessAllowed ? .green : .red)
                Text(formattedTime)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            if let source = matchedSource, let rule = matchedRule {
                HStack(spacing: 5) {
                    Image(nsImage: source.icon)
                        .resizable()
                        .frame(width: 14, height: 14)
                    Text(source.name)
                        .font(.caption)
                        .fontWeight(.medium)
                    Text(rule.protectedPathPrefix)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }

            processSection

            if !event.decisionReason.isEmpty {
                Text(event.decisionReason)
                    .font(.caption)
                    .foregroundColor(event.accessAllowed ? .secondary : Color.red.opacity(0.8))
                    .fixedSize(horizontal: false, vertical: true)
            }

            if !event.ancestors.isEmpty {
                ancestorsSection
            }
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 4)
        .background(
            RoundedRectangle(cornerRadius: 4)
                .fill(event.accessAllowed ? Color.green.opacity(0.05) : Color.red.opacity(0.1))
        )
    }

    // MARK: - Operation badge

    private var operationBadge: some View {
        Text(event.operation)
            .font(.caption2)
            .foregroundStyle(.purple)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(Color.purple.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }

    @ViewBuilder
    private var jailBadge: some View {
        if event.jailedRuleID != nil {
            Text(event.accessAllowed ? "jailed ✓" : "jailed ✗")
                .font(.caption2)
                .foregroundStyle(event.accessAllowed ? .green : .red)
                .padding(.horizontal, 5)
                .padding(.vertical, 2)
                .background((event.accessAllowed ? Color.green : Color.red).opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 3))
        }
    }

    // MARK: - Shared detail sections

    @ViewBuilder
    private var processSection: some View {
        HStack {
            Text("PID: \(event.processID)")
                .font(.caption)
                .foregroundColor(.secondary)
            Text("UID: \(event.uid)")
                .font(.caption)
                .foregroundColor(.secondary)
            if !processTarget.processPath.isEmpty {
                Text(processTarget.processPath)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
        }
        let target = processTarget
        if let viaSigningID = target.viaSigningID {
            Text("via \(viaSigningID)")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        let hasNoSignature = target.teamID.isEmpty && target.signingID.isEmpty
        HStack {
            Text("Team: \(hasNoSignature ? invalidSignature : target.teamID)")
                .font(.caption)
                .foregroundColor(.secondary)
            if hasNoSignature {
                Text("Signing: \(invalidSignature)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else if !target.signingID.isEmpty {
                if canAllowDeny, let ruleID = event.matchedRuleID, event.jailedRuleID == nil {
                    allowButton(
                        label: "Signing: \(target.signingID)",
                        itemKey: "process",
                        risk: target.allowRisk
                    ) {
                        try await PolicyStore.shared.allowProcess(
                            teamID: target.teamID,
                            signingID: target.signingID,
                            inRule: ruleID
                        )
                    }
                } else {
                    Text("Signing: \(target.signingID)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                if let url = suggestBaselineIssueURL {
                    Button { NSWorkspace.shared.open(url) } label: {
                        Label("Suggest for baseline", systemImage: "ladybug")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.mini)
                }
            }
        }
        if canQuietNotifications {
            allowButton(label: "Don't notify for this process", itemKey: "quiet", risk: .noKnownRisk) {
                try await QuietListStore.shared.add(
                    .quieting(processPath: target.processPath, signingID: target.signingID, teamID: target.teamID)
                )
            }
            .font(.caption)
        }
    }

    @ViewBuilder
    private var ancestorsSection: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(Array(event.ancestors.enumerated()), id: \.offset) { index, ancestor in
                let ancestorHasNoSignature = ancestor.teamID.isEmpty && ancestor.signingID.isEmpty
                HStack(spacing: 4) {
                    Text(String(repeating: "  ", count: index) + "↳")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(ancestor.path)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                        HStack {
                            Text("Team: \(ancestorHasNoSignature ? invalidSignature : ancestor.teamID)")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                            if ancestorHasNoSignature {
                                Text("Signing: \(invalidSignature)")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            } else if !ancestor.signingID.isEmpty {
                                if canAllowDeny, let ruleID = event.matchedRuleID, event.jailedRuleID == nil {
                                    allowButton(
                                        label: "Signing: \(ancestor.signingID)",
                                        itemKey: "ancestor-\(index)",
                                        risk: eventSignatureAllowRisk(teamID: ancestor.teamID, signingID: ancestor.signingID)
                                    ) {
                                        try await PolicyStore.shared.allowAncestor(
                                            teamID: ancestor.teamID,
                                            signingID: ancestor.signingID,
                                            inRule: ruleID
                                        )
                                    }
                                    .font(.caption2)
                                } else {
                                    Text("Signing: \(ancestor.signingID)")
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                        .lineLimit(1)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func allowButton(label: String, itemKey: String, risk: AllowRisk, action: @escaping () async throws -> Void) -> some View {
        if allowedItems.contains(itemKey) {
            Text(label)
                .strikethrough()
                .foregroundColor(.secondary)
        } else {
            Button {
                riskGate.submit([RiskReviewItem(label: label, risk: risk)]) {
                    Task {
                        do {
                            try await action()
                            allowedItems.insert(itemKey)
                        } catch {}
                    }
                }
            } label: {
                Text(label)
                    .underline()
                    .foregroundColor(.red.opacity(0.8))
            }
            .buttonStyle(.borderless)
        }
    }
}
