//
//  EventsWindowView.swift
//  clearancekit
//
//  Created by Craig J. Bass on 03/03/2026.
//

import SwiftUI

enum EventFilter: String, CaseIterable {
    case all = "All"
    case allow = "Allow"
    case deny = "Deny"
}

struct EventsWindowView: View {
    @StateObject private var xpcClient = XPCClient.shared
    @State private var filter: EventFilter = .all

    private var filteredEvents: [FolderOpenEvent] {
        switch filter {
        case .all:   return xpcClient.events
        case .allow: return xpcClient.events.filter { $0.accessAllowed }
        case .deny:  return xpcClient.events.filter { !$0.accessAllowed }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            eventList
        }
        .frame(minWidth: 600, minHeight: 400)
        .onAppear {
            xpcClient.fetchHistoricEvents()
        }
    }

    private var toolbar: some View {
        HStack {
            Picker("Filter", selection: $filter) {
                ForEach(EventFilter.allCases, id: \.self) { f in
                    Text(f.rawValue).tag(f)
                }
            }
            .pickerStyle(.segmented)
            .fixedSize()

            Spacer()

            Button("Load History") {
                xpcClient.fetchHistoricEvents()
            }

            Button("Clear") {
                xpcClient.clearEvents()
            }
        }
        .padding()
        .background(Color(NSColor.windowBackgroundColor))
    }

    private var eventList: some View {
        Group {
            if filteredEvents.isEmpty {
                VStack {
                    Spacer()
                    Text("No events")
                        .foregroundColor(.secondary)
                    if filter != .all {
                        Text("No \(filter.rawValue.lowercased()) events recorded")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    } else {
                        Text("Access a file in /opt/clearancekit to see FAA events")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                }
            } else {
                List(filteredEvents, id: \.eventID) { event in
                    EventRow(event: event)
                }
                .listStyle(.inset)
            }
        }
    }
}
