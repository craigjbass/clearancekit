//
//  ProcessesView.swift
//  clearancekit
//

import SwiftUI

// MARK: - ProcessesView

struct ProcessesView: View {
    @StateObject private var xpcClient = XPCClient.shared
    @StateObject private var jailStore = JailStore.shared
    @State private var knownProcesses: [pid_t: RunningProcessInfo] = [:]
    @State private var activeProcessPIDs: Set<pid_t> = []

    private var allRules: [JailRule] { jailStore.managedRules + jailStore.userRules }

    private var jailedTree: [JailedProcessNode] {
        buildJailedTree(
            from: Array(knownProcesses.values),
            activePIDs: activeProcessPIDs,
            rules: allRules,
            events: xpcClient.events
        )
    }

    private var flattenedJailedTree: [(node: JailedProcessNode, depth: Int)] {
        func flatten(_ nodes: [JailedProcessNode], depth: Int) -> [(node: JailedProcessNode, depth: Int)] {
            nodes.flatMap { node in [(node, depth)] + flatten(node.children ?? [], depth + 1) }
        }
        return flatten(jailedTree, 0)
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
                    ForEach(flattenedJailedTree, id: \.node.id) { item in
                        JailedProcessRow(node: item.node, depth: item.depth)
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
            let active = await xpcClient.fetchActiveJailedProcesses()
            for process in active {
                knownProcesses[pid_t(process.pid)] = process
            }
            activeProcessPIDs = Set(active.map { pid_t($0.pid) })
            try? await Task.sleep(for: .seconds(2))
        }
    }
}

// MARK: - DeniedJailAccess

private struct DeniedJailAccess: Identifiable {
    var id: String { "\(ruleID?.uuidString ?? ""):\(path)" }
    let path: String
    let ruleID: UUID?
    let count: Int
}

// MARK: - JailedProcessNode

private struct JailedProcessNode: Identifiable {
    let id: pid_t
    let process: RunningProcessInfo
    /// Non-nil when this process is the direct target of a jail rule.
    let matchedRule: JailRule?
    /// The rule in effect — either matchedRule or an ancestor's rule.
    let effectiveRule: JailRule?
    let deniedAccesses: [DeniedJailAccess]
    let isActive: Bool
    var children: [JailedProcessNode]?

    var name: String { URL(fileURLWithPath: process.path).lastPathComponent }
}

// MARK: - JailedProcessRow

private struct JailedProcessRow: View {
    let node: JailedProcessNode
    let depth: Int
    @State private var isExpanded = false

    var body: some View {
        if node.deniedAccesses.isEmpty {
            rowHeader
                .padding(.vertical, 3)
                .padding(.horizontal, 2)
        } else {
            DisclosureGroup(isExpanded: $isExpanded) {
                ForEach(node.deniedAccesses) { access in
                    DeniedJailAccessRow(access: access)
                }
            } label: {
                rowHeader
            }
            .padding(.vertical, 3)
            .padding(.horizontal, 2)
        }
    }

    private var rowHeader: some View {
        HStack(alignment: .top, spacing: 4) {
            if depth > 0 {
                Text(String(repeating: "  ", count: depth - 1) + "↳")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Circle()
                        .fill(node.isActive ? Color.green : Color.secondary)
                        .frame(width: 6, height: 6)
                    Text(node.name)
                        .fontWeight(.medium)
                    ruleBadge
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
        }
    }

    @ViewBuilder private var ruleBadge: some View {
        if let rule = node.matchedRule {
            Text(rule.name)
                .font(.caption2)
                .foregroundStyle(.orange)
                .padding(.horizontal, 5)
                .padding(.vertical, 2)
                .background(Color.orange.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 3))
        } else if let rule = node.effectiveRule {
            Text("↑ \(rule.name)")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 5)
                .padding(.vertical, 2)
                .background(Color.secondary.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 3))
        }
    }
}

// MARK: - DeniedJailAccessRow

private struct DeniedJailAccessRow: View {
    let access: DeniedJailAccess
    @StateObject private var jailStore = JailStore.shared
    @State private var isAllowing = false

    private var effectiveRule: JailRule? {
        guard let ruleID = access.ruleID else { return nil }
        return (jailStore.managedRules + jailStore.userRules).first { $0.id == ruleID }
    }

    private var isAlreadyCovered: Bool {
        guard let rule = effectiveRule else { return false }
        return checkJailPath(rule: rule, path: access.path).isAllowed
    }

    private var canAllow: Bool {
        guard let rule = effectiveRule else { return false }
        return rule.source == .user && !isAlreadyCovered
    }

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "xmark.circle.fill")
                .foregroundStyle(.red)
                .font(.caption2)
            Text(access.path)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer()
            if access.count > 1 {
                Text("×\(access.count)")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .padding(.horizontal, 4)
                    .padding(.vertical, 2)
                    .background(Color.red.opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 3))
            }
            allowControl
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder private var allowControl: some View {
        if isAlreadyCovered {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.caption)
        } else if canAllow {
            Button {
                Task {
                    isAllowing = true
                    if let ruleID = access.ruleID {
                        try? await jailStore.allowPath(access.path, inRule: ruleID)
                    }
                    isAllowing = false
                }
            } label: {
                Image(systemName: isAllowing ? "ellipsis.circle" : "plus.circle")
                    .foregroundStyle(.secondary)
                    .font(.caption)
            }
            .buttonStyle(.borderless)
            .disabled(isAllowing)
        }
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
    @State private var isAllowing = false
    @StateObject private var allowlistStore = AllowlistStore.shared

    private var displayTeamID: String {
        if group.teamID.isEmpty && group.signingID.isEmpty { return invalidSignature }
        return group.teamID.isEmpty ? "apple" : group.teamID
    }

    private var allowlistEntry: AllowlistEntry {
        AllowlistEntry(
            signingID: group.signingID,
            processPath: group.signingID.isEmpty ? group.processPath : "",
            platformBinary: group.teamID.isEmpty && !group.signingID.isEmpty,
            teamID: group.teamID
        )
    }

    private var isAlreadyAllowlisted: Bool {
        let all = allowlistStore.baselineEntries + allowlistStore.managedEntries + allowlistStore.userEntries
        return isGloballyAllowed(allowlist: all, processPath: group.processPath, signingID: group.signingID, teamID: group.teamID)
    }

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            ForEach(group.events, id: \.eventID) { event in
                EventRow(event: event, isHighlighted: false)
            }
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Image(systemName: "xmark.shield.fill")
                        .foregroundStyle(.red)
                    Text(group.name)
                        .fontWeight(.medium)
                    Spacer()
                    allowButton
                    Text("\(group.events.count)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Color.red.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                }
                HStack(spacing: 8) {
                    Text("Team: \(displayTeamID)")
                    if !group.signingID.isEmpty {
                        Text(group.signingID)
                            .lineLimit(1)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 4)
    }

    @ViewBuilder
    private var allowButton: some View {
        if isAlreadyAllowlisted {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.caption)
        } else {
            Button {
                Task {
                    isAllowing = true
                    try? await AllowlistStore.shared.add(allowlistEntry)
                    isAllowing = false
                }
            } label: {
                Image(systemName: isAllowing ? "ellipsis.circle" : "plus.circle")
                    .foregroundStyle(.secondary)
                    .font(.caption)
            }
            .buttonStyle(.borderless)
            .disabled(isAllowing)
        }
    }
}

// MARK: - Jailed tree building

private func buildJailedTree(
    from processes: [RunningProcessInfo],
    activePIDs: Set<pid_t>,
    rules: [JailRule],
    events: [FolderOpenEvent]
) -> [JailedProcessNode] {
    guard !processes.isEmpty else { return [] }

    // Group denied jail events by ruleID rather than by PID. A jail rule may jail
    // multiple process instances over time; the user needs to see all denied paths
    // for a rule regardless of which specific process instance triggered them.
    var deniedByRuleID: [UUID: [String: Int]] = [:]
    for event in events where !event.accessAllowed {
        guard let ruleID = event.jailedRuleID else { continue }
        var pathMap = deniedByRuleID[ruleID] ?? [:]
        pathMap[event.path, default: 0] += 1
        deniedByRuleID[ruleID] = pathMap
    }

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

    func buildNode(pid: pid_t, inheritedRule: JailRule?) -> JailedProcessNode? {
        guard let process = byPID[pid] else { return nil }
        let resolvedTeamID = process.teamID.isEmpty ? appleTeamID : process.teamID
        let matchedRule = rules.first {
            $0.jailedSignature.matches(resolvedTeamID: resolvedTeamID, signingID: process.signingID)
        }
        let effectiveRule = matchedRule ?? inheritedRule

        let pathMap = effectiveRule.flatMap { deniedByRuleID[$0.id] } ?? [:]
        let deniedAccesses = pathMap
            .map { path, count in DeniedJailAccess(path: path, ruleID: effectiveRule?.id, count: count) }
            .sorted { $0.path < $1.path }

        let children = (childPIDs[pid] ?? [])
            .compactMap { buildNode(pid: $0, inheritedRule: effectiveRule) }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }

        let isActive = activePIDs.contains(pid)

        // Prune inactive processes with no deny accesses and no children worth showing.
        guard isActive || !deniedAccesses.isEmpty || !children.isEmpty else { return nil }

        return JailedProcessNode(
            id: pid,
            process: process,
            matchedRule: matchedRule,
            effectiveRule: effectiveRule,
            deniedAccesses: deniedAccesses,
            isActive: isActive,
            children: children.isEmpty ? nil : children
        )
    }

    return roots
        .compactMap { buildNode(pid: pid_t($0.pid), inheritedRule: nil) }
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
