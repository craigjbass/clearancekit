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

private struct FlatProcessNode: Identifiable {
    let id: pid_t
    let process: SnapshotProcess
    let depth: Int
}

private struct AppBundle: Identifiable {
    let id: String   // full bundle path, e.g. /Applications/Terminal.app
    let name: String // display name without .app
    let processes: [FlatProcessNode]
}

private struct ProcessSnapshot {
    static let empty = ProcessSnapshot(appBundles: [], userProcesses: [], applePlatform: [], other: [])
    let appBundles: [AppBundle]
    let userProcesses: [FlatProcessNode]
    let applePlatform: [FlatProcessNode]
    let other: [FlatProcessNode]
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
                processSection("Applications", nodes: nil, bundles: snapshot.appBundles)
                processSection("User Processes", nodes: snapshot.userProcesses)
                processSection("Apple Platform", nodes: snapshot.applePlatform)
                processSection("Other", nodes: snapshot.other)
            }
            .listStyle(.inset)
        }
    }

    @ViewBuilder
    private func processSection(
        _ title: String,
        nodes: [FlatProcessNode]?,
        bundles: [AppBundle]? = nil
    ) -> some View {
        if let bundles, !bundles.isEmpty {
            Section(title) {
                ForEach(bundles) { bundle in
                    DisclosureGroup {
                        ForEach(bundle.processes) { node in
                            ProcessNodeRow(node: node)
                        }
                    } label: {
                        HStack {
                            Text(bundle.name)
                                .fontWeight(.semibold)
                            Text("(\(bundle.processes.count))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        } else if let nodes, !nodes.isEmpty {
            Section(title) {
                ForEach(nodes) { node in
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
    let node: FlatProcessNode

    var body: some View {
        HStack(alignment: .top, spacing: 4) {
            if node.depth > 0 {
                Spacer(minLength: CGFloat(node.depth - 1) * 14)
                Image(systemName: "arrow.turn.down.right")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .frame(width: 14)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(node.process.name)
                    .fontWeight(node.depth == 0 ? .medium : .regular)
                Text(node.process.path)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                HStack(spacing: 12) {
                    Text("Team: \(node.process.displayTeamID)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    if !node.process.signingID.isEmpty {
                        Text("Signing: \(node.process.signingID)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Text("PID \(node.process.id)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .padding(.vertical, 1)
    }
}

// MARK: - Tree building

private final class TreeNode {
    let process: SnapshotProcess
    var children: [TreeNode] = []
    init(_ process: SnapshotProcess) { self.process = process }
}

private func buildFlatNodes(from processes: [SnapshotProcess]) -> [FlatProcessNode] {
    let pids = Set(processes.map { $0.id })
    var nodes: [pid_t: TreeNode] = [:]
    for p in processes { nodes[p.id] = TreeNode(p) }

    var roots: [TreeNode] = []
    for p in processes {
        if pids.contains(p.parentPID), let parent = nodes[p.parentPID] {
            parent.children.append(nodes[p.id]!)
        } else {
            roots.append(nodes[p.id]!)
        }
    }

    sortChildren(roots)
    return flatten(roots, depth: 0)
}

private func sortChildren(_ nodes: [TreeNode]) {
    for node in nodes {
        node.children.sort {
            $0.process.name.localizedCaseInsensitiveCompare($1.process.name) == .orderedAscending
        }
        sortChildren(node.children)
    }
}

private func flatten(_ nodes: [TreeNode], depth: Int) -> [FlatProcessNode] {
    nodes.flatMap { node in
        [FlatProcessNode(id: node.process.id, process: node.process, depth: depth)]
        + flatten(node.children, depth: depth + 1)
    }
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
            .map { bundlePath, processes -> AppBundle in
                let name = URL(fileURLWithPath: bundlePath)
                    .deletingPathExtension()
                    .lastPathComponent
                return AppBundle(
                    id: bundlePath,
                    name: name,
                    processes: buildFlatNodes(from: processes)
                )
            }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }

        return ProcessSnapshot(
            appBundles: appBundles,
            userProcesses: buildFlatNodes(from: userProcesses),
            applePlatform: buildFlatNodes(from: applePlatform),
            other: buildFlatNodes(from: other)
        )
    }.value
}
