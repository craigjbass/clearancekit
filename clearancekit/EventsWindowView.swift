//
//  EventsWindowView.swift
//  clearancekit
//
//  Created by Craig J. Bass on 03/03/2026.
//

import SwiftUI

enum EventFilter: String, CaseIterable {
    case all = "All"
    case allow = "Allow"
    case deny = "Deny"
}

struct EventsWindowView: View {
    @StateObject private var xpcClient = XPCClient.shared
    @ObservedObject private var nav = NavigationState.shared
    @State private var filter: EventFilter = .all
    @State private var showDefaultAllows = false

    private var filteredEvents: [FolderOpenEvent] {
        let base: [FolderOpenEvent]
        switch filter {
        case .all:   base = xpcClient.events
        case .allow: base = xpcClient.events.filter { $0.accessAllowed }
        case .deny:  base = xpcClient.events.filter { !$0.accessAllowed }
        }
        guard showDefaultAllows else { return base.filter { !$0.accessAllowed || $0.matchedRuleID != nil } }
        return base
    }

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            eventList
        }
        .onAppear {
            xpcClient.fetchHistoricEvents()
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

            Toggle("Show default allows", isOn: $showDefaultAllows)
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
                            try? await Task.sleep(for: .seconds(2))
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

    private static let baselineRuleIDs: Set<UUID> = Set(faaPolicy.map(\.id))

    private var isBaselineEvent: Bool {
        guard let ruleID = event.matchedRuleID else { return false }
        return Self.baselineRuleIDs.contains(ruleID)
    }

    private var isManagedEvent: Bool {
        guard let ruleID = event.matchedRuleID else { return false }
        return PolicyStore.shared.managedRules.contains { $0.id == ruleID }
    }

    /// True for any event matched by a read-only policy tier (baseline or managed).
    private var isReadOnlyEvent: Bool { isBaselineEvent || isManagedEvent }

    private var canAllowDeny: Bool { !event.accessAllowed && !isReadOnlyEvent }

    private var formattedTime: String {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .medium
        return formatter.string(from: event.timestamp)
    }

    var body: some View {
        let row = isReadOnlyEvent ? AnyView(compactRow) : AnyView(fullRow)
        row.overlay(
            RoundedRectangle(cornerRadius: 4)
                .stroke(Color.orange, lineWidth: isHighlighted ? 2 : 0)
                .animation(.easeOut(duration: 0.3), value: isHighlighted)
        )
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
                    Text(event.path)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)
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
                Text(event.path)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                Spacer()
                Text(event.accessAllowed ? "Allowed" : "Denied")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(event.accessAllowed ? .green : .red)
                Text(formattedTime)
                    .font(.caption)
                    .foregroundColor(.secondary)
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

    // MARK: - Shared detail sections

    @ViewBuilder
    private var processSection: some View {
        HStack {
            Text("PID: \(event.processID)")
                .font(.caption)
                .foregroundColor(.secondary)
            if !event.processPath.isEmpty {
                Text(event.processPath)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
        }
        let hasNoSignature = event.teamID.isEmpty && event.signingID.isEmpty
        HStack {
            Text("Team: \(hasNoSignature ? invalidSignature : (event.teamID.isEmpty ? "apple" : event.teamID))")
                .font(.caption)
                .foregroundColor(.secondary)
            if hasNoSignature {
                Text("Signing: \(invalidSignature)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else if !event.signingID.isEmpty {
                if canAllowDeny, let ruleID = event.matchedRuleID {
                    allowButton(label: "Signing: \(event.signingID)", itemKey: "process") {
                        try await PolicyStore.shared.allowProcess(
                            teamID: event.teamID,
                            signingID: event.signingID,
                            inRule: ruleID
                        )
                    }
                } else {
                    Text("Signing: \(event.signingID)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
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
                            Text("Team: \(ancestorHasNoSignature ? invalidSignature : (ancestor.teamID.isEmpty ? "apple" : ancestor.teamID))")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                            if ancestorHasNoSignature {
                                Text("Signing: \(invalidSignature)")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            } else if !ancestor.signingID.isEmpty {
                                if canAllowDeny, let ruleID = event.matchedRuleID {
                                    allowButton(label: "Signing: \(ancestor.signingID)", itemKey: "ancestor-\(index)") {
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
    private func allowButton(label: String, itemKey: String, action: @escaping () async throws -> Void) -> some View {
        if allowedItems.contains(itemKey) {
            Text(label)
                .strikethrough()
                .foregroundColor(.secondary)
        } else {
            Button {
                Task {
                    do {
                        try await action()
                        allowedItems.insert(itemKey)
                    } catch {}
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
