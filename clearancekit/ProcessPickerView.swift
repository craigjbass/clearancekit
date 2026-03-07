//
//  ProcessPickerView.swift
//  clearancekit
//

import SwiftUI
import Security

// MARK: - RunningProcess

struct RunningProcess: Identifiable {
    let id: UUID
    let path: String
    let teamID: String
    let signingID: String
    let uid: uid_t

    var name: String { URL(fileURLWithPath: path).lastPathComponent }

    init(path: String, teamID: String, signingID: String, uid: uid_t) {
        self.id = UUID()
        self.path = path
        self.teamID = teamID
        self.signingID = signingID
        self.uid = uid
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
            processes = await enumerateRunningProcesses()
            isLoading = false
        }
    }

    private func enumerateRunningProcesses() async -> [RunningProcess] {
        await Task.detached(priority: .userInitiated) {
            let currentUID = getuid()

            let estimated = proc_listallpids(nil, 0)
            guard estimated > 0 else { return [] }
            var pids = [pid_t](repeating: 0, count: Int(estimated) + 64)
            let count = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size)))
            guard count > 0 else { return [] }

            var seen: Set<String> = []
            var result: [RunningProcess] = []

            for pid in pids.prefix(count) where pid > 0 {
                var bsdInfo = proc_bsdinfo()
                guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdInfo, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0 else { continue }
                let uid = bsdInfo.pbi_uid

                var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
                guard proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN)) > 0 else { continue }
                let path = String(cString: pathBuffer)
                guard !path.isEmpty else { continue }

                let (teamID, signingID) = codeSigningIDs(forPID: pid)

                let key = "\(path)|\(teamID)|\(signingID)"
                guard !seen.contains(key) else { continue }
                seen.insert(key)

                result.append(RunningProcess(path: path, teamID: teamID, signingID: signingID, uid: uid))
            }

            return result.sorted {
                let aIsOwn = $0.uid == currentUID
                let bIsOwn = $1.uid == currentUID
                if aIsOwn != bIsOwn { return aIsOwn }
                return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
            }
        }.value
    }

    private nonisolated func codeSigningIDs(forPID pid: pid_t) -> (teamID: String, signingID: String) {
        let attrs = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(rawValue: 0), &code) == errSecSuccess,
              let code else { return ("", "") }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(rawValue: 0), &staticCode) == errSecSuccess,
              let staticCode else { return ("", "") }
        var dict: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: 2), &dict) == errSecSuccess,
              let info = dict as? [CFString: Any] else { return ("", "") }
        let teamID = info[kSecCodeInfoTeamIdentifier] as? String ?? ""
        let signingID = info[kSecCodeInfoIdentifier] as? String ?? ""
        return (teamID, signingID)
    }
}
