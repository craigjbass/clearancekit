//
//  ProcessPickerView.swift
//  clearancekit
//

import SwiftUI

// MARK: - RunningProcess

struct RunningProcess: Identifiable {
    let id: UUID
    let path: String
    let teamID: String
    let signingID: String
    let uid: uid_t

    var name: String { URL(fileURLWithPath: path).lastPathComponent }

    init(_ info: RunningProcessInfo) {
        self.id = UUID()
        self.path = info.path
        self.teamID = info.teamID
        self.signingID = info.signingID
        self.uid = info.uid
    }
}

// MARK: - ProcessPickerView

struct ProcessPickerView: View {
    let onSelect: (RunningProcess) -> Void
    let onCancel: () -> Void

    @State private var processes: [RunningProcess] = []
    @State private var searchText = ""
    @State private var isLoading = true

    private var filtered: [RunningProcess] {
        guard !searchText.isEmpty else { return processes }
        let query = searchText.lowercased()
        return processes.filter {
            $0.path.lowercased().contains(query) ||
            $0.teamID.lowercased().contains(query) ||
            $0.signingID.lowercased().contains(query)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Pick Running Process")
                    .font(.headline)
                Spacer()
                Button("Cancel", action: onCancel)
            }
            .padding()

            Divider()

            TextField("Search by name, path, team ID, or signing ID", text: $searchText)
                .textFieldStyle(.roundedBorder)
                .padding(.horizontal)
                .padding(.vertical, 8)

            if isLoading {
                Spacer()
                ProgressView("Enumerating processes...")
                Spacer()
            } else {
                List(filtered) { process in
                    Button {
                        onSelect(process)
                    } label: {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(process.name)
                                .fontWeight(.medium)
                            Text(process.path)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                            if !process.teamID.isEmpty || !process.signingID.isEmpty {
                                HStack(spacing: 12) {
                                    if !process.teamID.isEmpty {
                                        Text("Team: \(process.teamID)")
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                    }
                                    if !process.signingID.isEmpty {
                                        Text("Signing: \(process.signingID)")
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .frame(width: 560, height: 500)
        .task {
            let currentUID = getuid()
            let raw = await XPCClient.shared.fetchProcessList()
            var seen: Set<String> = []
            var result: [RunningProcess] = []
            for info in raw {
                let key = "\(info.path)|\(info.teamID)|\(info.signingID)"
                guard !seen.contains(key) else { continue }
                seen.insert(key)
                result.append(RunningProcess(info))
            }
            processes = result.sorted {
                let aIsOwn = $0.uid == currentUID
                let bIsOwn = $1.uid == currentUID
                if aIsOwn != bIsOwn { return aIsOwn }
                return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
            }
            isLoading = false
        }
    }
}
