//
//  ProcessTreeView.swift
//  clearancekit
//

import SwiftUI

extension RunningProcessInfo: @retroactive Identifiable {
    public var id: String { "\(pid).\(pidVersion)" }
}

struct ProcessTreeView: View {
    private static let monoBody    = Font.system(.body,    design: .monospaced)
    private static let monoCaption = Font.system(.caption, design: .monospaced)

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

    @TableColumnBuilder<RunningProcessInfo, KeyPathComparator<RunningProcessInfo>>
    private var processColumns: some TableColumnContent<RunningProcessInfo, KeyPathComparator<RunningProcessInfo>> {
        TableColumn("PID", value: \.pid) { r -> Text in
            Text(String(r.pid)).font(Self.monoBody)
        }
        .width(60)
        TableColumn("PID Version", value: \.pidVersion) { r -> Text in
            Text(String(r.pidVersion)).font(Self.monoCaption).foregroundStyle(.secondary)
        }
        .width(40)
        TableColumn("PPID", value: \.parentPID) { r -> Text in
            Text(String(r.parentPID)).font(Self.monoBody)
        }
        .width(60)
        TableColumn("PPID Version", value: \.parentPIDVersion) { r -> Text in
            Text(String(r.parentPIDVersion)).font(Self.monoCaption).foregroundStyle(.secondary)
        }
        .width(40)
        TableColumn("Name") { r -> Text in
            Text(URL(fileURLWithPath: r.path).lastPathComponent)
        }
        .width(min: 100, ideal: 160)
    }

    @TableColumnBuilder<RunningProcessInfo, KeyPathComparator<RunningProcessInfo>>
    private var identifierColumns: some TableColumnContent<RunningProcessInfo, KeyPathComparator<RunningProcessInfo>> {
        TableColumn("Path", value: \.path) { r -> Text in
            Text(r.path).font(Self.monoCaption).foregroundStyle(.secondary)
        }
        .width(min: 180, ideal: 300)
        TableColumn("Signing ID", value: \.signingID) { r -> Text in
            Text(r.signingID.isEmpty ? "—" : r.signingID).font(Self.monoCaption)
        }
        .width(min: 120, ideal: 200)
        TableColumn("Team ID", value: \.teamID) { r -> Text in
            Text(r.teamID.isEmpty ? "—" : r.teamID).font(Self.monoCaption)
        }
        .width(90)
        TableColumn("UID", value: \.uid) { r -> Text in
            Text(String(r.uid)).font(Self.monoCaption)
        }
        .width(40)
        TableColumn("GID", value: \.gid) { r -> Text in
            Text(String(r.gid)).font(Self.monoCaption)
        }
        .width(40)
    }

    var body: some View {
        Table(filteredRecords.sorted(using: sortOrder), selection: $selectedProcessID, sortOrder: $sortOrder) {
            processColumns
            identifierColumns
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
