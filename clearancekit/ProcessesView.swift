//
//  ProcessesView.swift
//  clearancekit
//

import SwiftUI
import Security

// MARK: - Data models

private struct SnapshotProcess: Identifiable {
    let id: pid_t
    let parentPID: pid_t
    let path: String
    let teamID: String
    let signingID: String
    let uid: uid_t

    var name: String { URL(fileURLWithPath: path).lastPathComponent }
    var displayTeamID: String { teamID.isEmpty ? "Apple" : teamID }

    var appBundlePath: String? {
        let parts = path.components(separatedBy: "/")
        guard let appIdx = parts.firstIndex(where: { $0.hasSuffix(".app") }) else { return nil }
        return "/" + parts[1...appIdx].joined(separator: "/")
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
        snapshot = await buildSnapshot()
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
                    if !p.signingID.isEmpty {
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

// MARK: - Snapshot enumeration

private func buildSnapshot() async -> ProcessSnapshot {
    await Task.detached(priority: .userInitiated) {
        let currentUID = getuid()

        let estimated = proc_listallpids(nil, 0)
        guard estimated > 0 else { return .empty }
        var pids = [pid_t](repeating: 0, count: Int(estimated) + 64)
        let count = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size)))
        guard count > 0 else { return .empty }

        var all: [pid_t: SnapshotProcess] = [:]
        all.reserveCapacity(count)

        for pid in pids.prefix(count) where pid > 0 {
            var bsdInfo = proc_bsdinfo()
            guard proc_pidinfo(
                pid, PROC_PIDTBSDINFO, 0,
                &bsdInfo, Int32(MemoryLayout<proc_bsdinfo>.size)
            ) > 0 else { continue }

            var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            guard proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN)) > 0 else { continue }
            let path = String(cString: pathBuffer)
            guard !path.isEmpty else { continue }

            let (teamID, signingID) = codeSigningIDs(forPID: pid)

            all[pid] = SnapshotProcess(
                id: pid,
                parentPID: pid_t(bsdInfo.pbi_ppid),
                path: path,
                teamID: teamID,
                signingID: signingID,
                uid: bsdInfo.pbi_uid
            )
        }

        var bundleMap: [String: [SnapshotProcess]] = [:]
        var userProcesses: [SnapshotProcess] = []
        var applePlatform: [SnapshotProcess] = []
        var other: [SnapshotProcess] = []

        for process in all.values {
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
            .map { bundlePath, processes -> ProcessNode in
                let name = URL(fileURLWithPath: bundlePath)
                    .deletingPathExtension()
                    .lastPathComponent
                let children = buildProcessNodes(from: processes)
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
    }.value
}
