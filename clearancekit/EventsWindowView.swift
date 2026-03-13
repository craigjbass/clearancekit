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
                    } else {
                        Text("Access a file in /opt/clearancekit to see FAA events")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                }
            } else {
                List(filteredEvents, id: \.eventID) { event in
                    EventRow(event: event)
                }
                .listStyle(.inset)
            }
        }
    }
}

// MARK: - EventRow

struct EventRow: View {
    let event: FolderOpenEvent
    @State private var allowedItems: Set<String> = []

    private var formattedTime: String {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .medium
        return formatter.string(from: event.timestamp)
    }

    var body: some View {
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

    @ViewBuilder
    private var processSection: some View {
        HStack(alignment: .top, spacing: 4) {
            VStack(alignment: .leading, spacing: 2) {
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
                HStack {
                    Text("Team: \(event.teamID.isEmpty ? "Apple" : event.teamID)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    if !event.signingID.isEmpty {
                        Text("Signing: \(event.signingID)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            if !event.accessAllowed, let ruleID = event.matchedRuleID {
                Spacer()
                allowButton(itemKey: "process") {
                    PolicyStore.shared.allowProcess(
                        teamID: event.teamID,
                        signingID: event.signingID,
                        inRule: ruleID
                    )
                }
            }
        }
    }

    @ViewBuilder
    private var ancestorsSection: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(Array(event.ancestors.enumerated()), id: \.offset) { index, ancestor in
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
                            Text("Team: \(ancestor.teamID.isEmpty ? "Apple" : ancestor.teamID)")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                            if !ancestor.signingID.isEmpty {
                                Text("Signing: \(ancestor.signingID)")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                                    .lineLimit(1)
                            }
                        }
                    }
                    if !event.accessAllowed, let ruleID = event.matchedRuleID {
                        Spacer()
                        allowButton(itemKey: "ancestor-\(index)") {
                            PolicyStore.shared.allowAncestor(
                                teamID: ancestor.teamID,
                                signingID: ancestor.signingID,
                                inRule: ruleID
                            )
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func allowButton(itemKey: String, action: @escaping () -> Void) -> some View {
        if allowedItems.contains(itemKey) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.caption)
        } else {
            Button {
                action()
                allowedItems.insert(itemKey)
            } label: {
                Label("Allow", systemImage: "plus.circle")
                    .font(.caption)
            }
            .buttonStyle(.borderless)
        }
    }
}
