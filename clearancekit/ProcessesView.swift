//
//  ProcessesView.swift
//  clearancekit
//

import SwiftUI

// MARK: - Data models

private struct SnapshotProcess: Identifiable {
    let id: pid_t
    let parentPID: pid_t
    let path: String
    let teamID: String
    let signingID: String
    let uid: uid_t

    var name: String { URL(fileURLWithPath: path).lastPathComponent }
    var displayTeamID: String {
        if teamID.isEmpty && signingID.isEmpty { return invalidSignature }
        return teamID.isEmpty ? "apple" : teamID
    }

    var appBundlePath: String? {
        let parts = path.components(separatedBy: "/")
        guard let appIdx = parts.firstIndex(where: { $0.hasSuffix(".app") }) else { return nil }
        return "/" + parts[1...appIdx].joined(separator: "/")
    }

    init(_ info: RunningProcessInfo) {
        self.id = info.pid
        self.parentPID = info.parentPID
        self.path = info.path
        self.teamID = info.teamID
        self.signingID = info.signingID
        self.uid = info.uid
    }
}

private struct ProcessNode: Identifiable {
    enum Kind {
        case bundle(name: String)
        case process(SnapshotProcess)
    }
    let id: String
    let kind: Kind
    var children: [ProcessNode]?   // nil = leaf; OutlineGroup shows no disclosure for nil
}

private struct ProcessSnapshot {
    static let empty = ProcessSnapshot(appBundles: [], userProcesses: [], applePlatform: [], other: [])
    let appBundles: [ProcessNode]    // each is a .bundle node with .process children
    let userProcesses: [ProcessNode]
    let applePlatform: [ProcessNode]
    let other: [ProcessNode]
}

// MARK: - ProcessesView

struct ProcessesView: View {
    @State private var snapshot: ProcessSnapshot = .empty
    @State private var isLoading = false

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            content
        }
        .task { await load() }
    }

    private var toolbar: some View {
        HStack {
            Spacer()
            if isLoading {
                ProgressView()
                    .scaleEffect(0.7)
                    .padding(.trailing, 4)
            }
            Button("Refresh") { Task { await load() } }
                .disabled(isLoading)
        }
        .padding()
        .background(Color(NSColor.windowBackgroundColor))
    }

    @ViewBuilder
    private var content: some View {
        if isLoading && snapshot.appBundles.isEmpty && snapshot.userProcesses.isEmpty
            && snapshot.applePlatform.isEmpty && snapshot.other.isEmpty {
            VStack {
                Spacer()
                ProgressView("Loading processes...")
                Spacer()
            }
        } else {
            List {
                outlineSection("Applications", nodes: snapshot.appBundles)
                outlineSection("User Processes", nodes: snapshot.userProcesses)
                outlineSection("Apple Platform", nodes: snapshot.applePlatform)
                outlineSection("Other", nodes: snapshot.other)
            }
            .listStyle(.inset)
        }
    }

    @ViewBuilder
    private func outlineSection(_ title: String, nodes: [ProcessNode]) -> some View {
        if !nodes.isEmpty {
            Section(title) {
                OutlineGroup(nodes, children: \.children) { node in
                    ProcessNodeRow(node: node)
                }
            }
        }
    }

    private func load() async {
        isLoading = true
        let rawProcesses = await XPCClient.shared.fetchProcessList()
        snapshot = buildSnapshot(from: rawProcesses.map(SnapshotProcess.init))
        isLoading = false
    }
}

// MARK: - ProcessNodeRow

private struct ProcessNodeRow: View {
    let node: ProcessNode

    var body: some View {
        switch node.kind {
        case .bundle(let name):
            HStack {
                Text(name)
                    .fontWeight(.semibold)
                if let count = node.children?.count {
                    Text("\(count) processes")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        case .process(let p):
            VStack(alignment: .leading, spacing: 2) {
                Text(p.name)
                Text(p.path)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                HStack(spacing: 12) {
                    Text("Team: \(p.displayTeamID)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    if p.teamID.isEmpty && p.signingID.isEmpty {
                        Text("Signing: \(invalidSignature)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    } else if !p.signingID.isEmpty {
                        Text("Signing: \(p.signingID)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Text("PID \(p.id)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
            .padding(.vertical, 1)
        }
    }
}

// MARK: - Tree building

private final class TreeNode {
    let process: SnapshotProcess
    var children: [TreeNode] = []
    init(_ process: SnapshotProcess) { self.process = process }
}

private func buildProcessNodes(from processes: [SnapshotProcess]) -> [ProcessNode] {
    let pids = Set(processes.map { $0.id })
    var treeNodes: [pid_t: TreeNode] = [:]
    for p in processes { treeNodes[p.id] = TreeNode(p) }

    var roots: [TreeNode] = []
    for p in processes {
        if pids.contains(p.parentPID), let parent = treeNodes[p.parentPID] {
            parent.children.append(treeNodes[p.id]!)
        } else {
            roots.append(treeNodes[p.id]!)
        }
    }

    sortTreeNodes(&roots)
    return roots.map(toProcessNode)
}

private func sortTreeNodes(_ nodes: inout [TreeNode]) {
    nodes.sort {
        $0.process.name.localizedCaseInsensitiveCompare($1.process.name) == .orderedAscending
    }
    for node in nodes { sortTreeNodes(&node.children) }
}

private func toProcessNode(_ tree: TreeNode) -> ProcessNode {
    let children = tree.children.map(toProcessNode)
    return ProcessNode(
        id: "\(tree.process.id)",
        kind: .process(tree.process),
        children: children.isEmpty ? nil : children
    )
}

// MARK: - Snapshot building

private func buildSnapshot(from processes: [SnapshotProcess]) -> ProcessSnapshot {
    let currentUID = getuid()

    var bundleMap: [String: [SnapshotProcess]] = [:]
    var userProcesses: [SnapshotProcess] = []
    var applePlatform: [SnapshotProcess] = []
    var other: [SnapshotProcess] = []

    for process in processes {
        if let bundlePath = process.appBundlePath {
            bundleMap[bundlePath, default: []].append(process)
        } else if process.uid == currentUID {
            userProcesses.append(process)
        } else if process.teamID.isEmpty {
            applePlatform.append(process)
        } else {
            other.append(process)
        }
    }

    let appBundles = bundleMap
        .map { bundlePath, procs -> ProcessNode in
            let name = URL(fileURLWithPath: bundlePath)
                .deletingPathExtension()
                .lastPathComponent
            let children = buildProcessNodes(from: procs)
            return ProcessNode(
                id: bundlePath,
                kind: .bundle(name: name),
                children: children.isEmpty ? nil : children
            )
        }
        .sorted { lhs, rhs in
            guard case .bundle(let a) = lhs.kind, case .bundle(let b) = rhs.kind else { return false }
            return a.localizedCaseInsensitiveCompare(b) == .orderedAscending
        }

    return ProcessSnapshot(
        appBundles: appBundles,
        userProcesses: buildProcessNodes(from: userProcesses),
        applePlatform: buildProcessNodes(from: applePlatform),
        other: buildProcessNodes(from: other)
    )
}
