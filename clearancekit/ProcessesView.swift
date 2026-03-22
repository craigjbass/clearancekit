//
//  ProcessesView.swift
//  clearancekit
//

import SwiftUI

// MARK: - ProcessesView

struct ProcessesView: View {
    @StateObject private var xpcClient = XPCClient.shared
    @StateObject private var jailStore = JailStore.shared
    @State private var jailedProcesses: [RunningProcessInfo] = []

    private var jailedTree: [JailedProcessNode] {
        buildJailedTree(from: jailedProcesses, rules: jailStore.userRules)
    }

    private var denyGroups: [DenyGroup] {
        buildDenyGroups(from: xpcClient.events)
    }

    var body: some View {
        Group {
            if jailedTree.isEmpty && denyGroups.isEmpty {
                emptyState
            } else {
                activityList
            }
        }
        .navigationTitle("Processes")
        .task { await pollJailedProcesses() }
    }

    private var activityList: some View {
        List {
            if !jailedTree.isEmpty {
                Section("Jailed Processes") {
                    OutlineGroup(jailedTree, children: \.children) { node in
                        JailedProcessRow(node: node)
                    }
                }
            }
            if !denyGroups.isEmpty {
                Section("Denied Processes") {
                    ForEach(denyGroups) { group in
                        DenyGroupRow(group: group)
                    }
                }
            }
        }
        .listStyle(.inset)
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Spacer()
            Text("No activity")
                .foregroundStyle(.secondary)
            Text(jailStore.userRules.isEmpty
                ? "Configure jail rules to start monitoring jailed processes."
                : "No jailed processes are currently running and no deny events have been recorded.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private func pollJailedProcesses() async {
        while !Task.isCancelled {
            jailedProcesses = await xpcClient.fetchActiveJailedProcesses()
            try? await Task.sleep(for: .seconds(2))
        }
    }
}

// MARK: - JailedProcessNode

private struct JailedProcessNode: Identifiable {
    let id: pid_t
    let process: RunningProcessInfo
    let matchedRule: JailRule?
    var children: [JailedProcessNode]?

    var name: String { URL(fileURLWithPath: process.path).lastPathComponent }
}

// MARK: - JailedProcessRow

private struct JailedProcessRow: View {
    let node: JailedProcessNode

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(node.name)
                    .fontWeight(.medium)
                if let rule = node.matchedRule {
                    Text(rule.name)
                        .font(.caption2)
                        .foregroundStyle(.orange)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Color.orange.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                } else {
                    Text("inherited")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                }
                Spacer()
                Text("PID \(node.process.pid)")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            Text(node.process.path)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(.vertical, 2)
    }
}

// MARK: - DenyGroup

private struct DenyGroup: Identifiable {
    let id: String
    let processPath: String
    let teamID: String
    let signingID: String
    let events: [FolderOpenEvent]

    var name: String { URL(fileURLWithPath: processPath).lastPathComponent }
}

// MARK: - DenyGroupRow

private struct DenyGroupRow: View {
    let group: DenyGroup
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { isExpanded.toggle() }
            } label: {
                HStack {
                    Image(systemName: "xmark.shield.fill")
                        .foregroundStyle(.red)
                    Text(group.name)
                        .fontWeight(.medium)
                    if !group.signingID.isEmpty {
                        Text(group.signingID)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                    Text("\(group.events.count)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Color.red.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .buttonStyle(.plain)

            if isExpanded {
                VStack(spacing: 0) {
                    ForEach(group.events, id: \.eventID) { event in
                        Divider()
                        EventRow(event: event, isHighlighted: false)
                            .padding(.leading, 12)
                    }
                }
            }
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 4)
    }
}

// MARK: - Jailed tree building

private func buildJailedTree(from processes: [RunningProcessInfo], rules: [JailRule]) -> [JailedProcessNode] {
    guard !processes.isEmpty else { return [] }

    let jailedPIDs = Set(processes.map { pid_t($0.pid) })
    var childPIDs: [pid_t: [pid_t]] = [:]
    for p in processes { childPIDs[pid_t(p.pid)] = [] }
    for p in processes {
        let parentPID = pid_t(p.parentPID)
        if jailedPIDs.contains(parentPID) {
            childPIDs[parentPID]?.append(pid_t(p.pid))
        }
    }

    let byPID = Dictionary(uniqueKeysWithValues: processes.map { (pid_t($0.pid), $0) })
    let roots = processes.filter { !jailedPIDs.contains(pid_t($0.parentPID)) }

    func buildNode(pid: pid_t) -> JailedProcessNode? {
        guard let process = byPID[pid] else { return nil }
        let resolvedTeamID = process.teamID.isEmpty ? appleTeamID : process.teamID
        let rule = rules.first { $0.jailedSignature.matches(resolvedTeamID: resolvedTeamID, signingID: process.signingID) }
        let children = (childPIDs[pid] ?? [])
            .compactMap { buildNode(pid: $0) }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        return JailedProcessNode(
            id: pid,
            process: process,
            matchedRule: rule,
            children: children.isEmpty ? nil : children
        )
    }

    return roots
        .compactMap { buildNode(pid: pid_t($0.pid)) }
        .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
}

// MARK: - Deny group building

private func buildDenyGroups(from events: [FolderOpenEvent]) -> [DenyGroup] {
    let denies = events.filter { !$0.accessAllowed && $0.jailedRuleID == nil }
    guard !denies.isEmpty else { return [] }

    var buckets: [String: (path: String, teamID: String, signingID: String, events: [FolderOpenEvent])] = [:]
    for event in denies {
        let key = event.signingID.isEmpty ? event.processPath : event.signingID
        if buckets[key] == nil {
            buckets[key] = (path: event.processPath, teamID: event.teamID, signingID: event.signingID, events: [])
        }
        buckets[key]?.events.append(event)
    }

    return buckets
        .map { key, value in
            DenyGroup(id: key, processPath: value.path, teamID: value.teamID, signingID: value.signingID, events: value.events)
        }
        .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
}
