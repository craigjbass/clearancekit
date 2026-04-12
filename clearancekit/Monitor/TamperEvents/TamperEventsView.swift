//
//  TamperEventsView.swift
//  clearancekit
//

import SwiftUI

struct TamperEventsView: View {
    @StateObject private var xpcClient = XPCClient.shared

    var body: some View {
        Group {
            if xpcClient.tamperEvents.isEmpty {
                emptyState
            } else {
                eventList
            }
        }
        .navigationTitle("Tamper Events")
        .onAppear {
            xpcClient.fetchHistoricTamperEvents()
        }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Spacer()
            Text("No tamper attempts recorded")
                .foregroundStyle(.secondary)
            Text("Tamper attempts against the opfilter process will appear here.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var eventList: some View {
        List(xpcClient.tamperEvents, id: \.eventID) { event in
            TamperEventRow(event: event)
        }
        .listStyle(.inset)
    }
}

// MARK: - TamperEventRow

private struct TamperEventRow: View {
    let event: TamperAttemptEvent

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.shield.fill")
                .foregroundStyle(.red)
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(event.signingID.isEmpty ? "Unknown process" : event.signingID)
                        .fontWeight(.medium)
                    Spacer()
                    Text(event.timestamp, style: .relative)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                HStack(spacing: 8) {
                    Text("PID \(event.sourcePID) v\(event.sourcePIDVersion)")
                    if !event.teamID.isEmpty {
                        Text("Team: \(event.teamID)")
                    }
                    Text(event.esEventType)
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }
}
