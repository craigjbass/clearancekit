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
    @State private var searchText = ""

    private var filteredRecords: [RunningProcessInfo] {
        guard !searchText.isEmpty else { return records }
        return records.filter { r in
            let name = URL(fileURLWithPath: r.path).lastPathComponent
            return [
                String(r.pid), String(r.pidVersion), String(r.parentPID), String(r.parentPIDVersion),
                name, r.path, r.signingID, r.teamID,
                String(r.uid), String(r.gid)
            ].contains { $0.localizedCaseInsensitiveContains(searchText) }
        }
    }

    var body: some View {
        Table(filteredRecords.sorted(using: sortOrder), selection: $selectedProcessID, sortOrder: $sortOrder) {
            Group {
                TableColumn("PID", value: \.pid) { r in
                    Text(String(r.pid)).font(.system(.body, design: .monospaced))
                }
                .width(60)
                TableColumn("PID Version", value: \.pidVersion) { r in
                    Text(String(r.pidVersion)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                }
                .width(40)
                TableColumn("PPID", value: \.parentPID) { r in
                    Text(String(r.parentPID)).font(.system(.body, design: .monospaced))
                }
                .width(60)
                TableColumn("PPID Version", value: \.parentPIDVersion) { r in
                    Text(String(r.parentPIDVersion)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                }
                .width(40)
                TableColumn("Name") { r in
                    Text(URL(fileURLWithPath: r.path).lastPathComponent)
                }
                .width(min: 100, ideal: 160)
            }
            Group {
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
        }
        .navigationTitle("Process Tree")
        .toolbar {
            ToolbarItem {
                Text(searchText.isEmpty ? "\(records.count) processes" : "\(filteredRecords.count) of \(records.count)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .contentMargins(.left, 4)
            }
            ToolbarItem {
                TextField("Search", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)
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
