//
//  ProcessTreeView.swift
//  clearancekit
//

import SwiftUI

extension RunningProcessInfo: @retroactive Identifiable {
    public var id: String { "\(pid).\(pidVersion)" }
}

struct ProcessTreeView: View {
    @StateObject private var xpcClient = XPCClient.shared
    @State private var records: [RunningProcessInfo] = []
    @State private var isLoading = false
    @State private var sortOrder = [KeyPathComparator(\RunningProcessInfo.pid)]
    @State private var selectedProcessID: RunningProcessInfo.ID?
    @State private var wizardProcess: RunningProcessInfo?

    var body: some View {
        Table(records.sorted(using: sortOrder), selection: $selectedProcessID, sortOrder: $sortOrder) {
            TableColumn("PID", value: \.pid) { r in
                Text(String(r.pid)).font(.system(.body, design: .monospaced))
            }
            .width(60)
            TableColumn("Ver", value: \.pidVersion) { r in
                Text(String(r.pidVersion)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
            }
            .width(40)
            TableColumn("PPID", value: \.parentPID) { r in
                Text(String(r.parentPID)).font(.system(.body, design: .monospaced))
            }
            .width(60)
            TableColumn("Name") { r in
                Text(URL(fileURLWithPath: r.path).lastPathComponent)
            }
            .width(min: 100, ideal: 160)
            TableColumn("Path", value: \.path) { r in
                Text(r.path).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
            }
            .width(min: 180, ideal: 300)
            TableColumn("Signing ID", value: \.signingID) { r in
                Text(r.signingID.isEmpty ? "—" : r.signingID).font(.system(.caption, design: .monospaced))
            }
            .width(min: 120, ideal: 200)
            TableColumn("Team ID", value: \.teamID) { r in
                Text(r.teamID.isEmpty ? "—" : r.teamID).font(.system(.caption, design: .monospaced))
            }
            .width(90)
            TableColumn("UID", value: \.uid) { r in
                Text(String(r.uid)).font(.system(.caption, design: .monospaced))
            }
            .width(40)
            TableColumn("GID", value: \.gid) { r in
                Text(String(r.gid)).font(.system(.caption, design: .monospaced))
            }
            .width(40)
        }
        .navigationTitle("Process Tree")
        .toolbar {
            ToolbarItem {
                Text("\(records.count) processes")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            ToolbarItem {
                Button {
                    Task { await load() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(isLoading)
            }
        }
        .task { await load() }
        .onChange(of: selectedProcessID) { _, newID in
            guard let id = newID,
                  let process = records.first(where: { $0.id == id }) else { return }
            wizardProcess = process
            selectedProcessID = nil
        }
        .sheet(item: $wizardProcess) { process in
            ProcessTreeWizardSheet(process: process)
        }
    }

    private func load() async {
        isLoading = true
        records = await xpcClient.fetchProcessTree()
        isLoading = false
    }
}
