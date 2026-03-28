//
//  AppPickerView.swift
//  clearancekit
//

import SwiftUI
import AppKit

struct AppPickerView: View {
    let onSelect: (URL) -> Void
    let onCancel: () -> Void

    @State private var apps: [AppEntry] = []
    @State private var searchText = ""

    private struct AppEntry: Identifiable {
        let url: URL
        let name: String
        let icon: NSImage
        var id: URL { url }
    }

    private var filtered: [AppEntry] {
        guard !searchText.isEmpty else { return apps }
        return apps.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Add Application")
                    .font(.headline)
                Spacer()
                Button("Cancel", action: onCancel)
            }
            .padding()

            Divider()

            TextField("Search", text: $searchText)
                .textFieldStyle(.roundedBorder)
                .padding(.horizontal)
                .padding(.vertical, 8)

            List(filtered) { app in
                Button {
                    onSelect(app.url)
                } label: {
                    HStack(spacing: 10) {
                        Image(nsImage: app.icon)
                            .resizable()
                            .frame(width: 32, height: 32)
                        Text(app.name)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .frame(width: 420, height: 500)
        .onAppear(perform: loadApps)
    }

    private func loadApps() {
        let fm = FileManager.default
        let dirs: [URL] = [
            URL(fileURLWithPath: "/Applications"),
            fm.homeDirectoryForCurrentUser.appendingPathComponent("Applications")
        ]
        var entries: [AppEntry] = []
        for dir in dirs {
            guard let contents = try? fm.contentsOfDirectory(
                at: dir,
                includingPropertiesForKeys: nil,
                options: .skipsHiddenFiles
            ) else { continue }
            for url in contents where url.pathExtension == "app" {
                let name = url.deletingPathExtension().lastPathComponent
                let icon = NSWorkspace.shared.icon(forFile: url.path)
                entries.append(AppEntry(url: url, name: name, icon: icon))
            }
        }
        apps = entries.sorted { $0.name.localizedCompare($1.name) == .orderedAscending }
    }
}
