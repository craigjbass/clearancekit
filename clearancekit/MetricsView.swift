//
//  MetricsView.swift
//  clearancekit
//

import SwiftUI
import Charts

struct MetricsView: View {
    @StateObject private var xpcClient = XPCClient.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Pipeline throughput — events per second over the last 60 seconds")
                .font(.callout)
                .foregroundStyle(.secondary)
                .padding()
            Divider()
            if xpcClient.metricsHistory.count < 2 {
                waitingPlaceholder
            } else {
                throughputChart
            }
        }
        .navigationTitle("Metrics")
    }

    // MARK: - Subviews

    private var waitingPlaceholder: some View {
        VStack {
            Spacer()
            Text("Waiting for data from extension…")
                .foregroundStyle(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var throughputChart: some View {
        Chart(chartData) { point in
            LineMark(
                x: .value("Time", point.timestamp),
                y: .value("Events/s", point.rate)
            )
            .foregroundStyle(by: .value("Series", point.series))
            .interpolationMethod(.catmullRom)
        }
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 6)) { _ in
                AxisGridLine()
                AxisTick()
                AxisValueLabel(format: .dateTime.hour().minute().second())
            }
        }
        .chartYAxisLabel("Events / s")
        .chartLegend(position: .topLeading)
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Data

    private struct ChartPoint: Identifiable {
        let id: String
        let timestamp: Date
        let rate: Double
        let series: String
    }

    private var chartData: [ChartPoint] {
        let history = xpcClient.metricsHistory
        guard history.count >= 2 else { return [] }
        var points: [ChartPoint] = []
        for i in 1..<history.count {
            let curr = history[i]
            let prev = history[i - 1]
            let t = curr.timestamp
            let key = String(t.timeIntervalSince1970)

            let hot  = curr.hotPathProcessedCount  >= prev.hotPathProcessedCount
                     ? Double(curr.hotPathProcessedCount  - prev.hotPathProcessedCount)  : 0
            let slow = curr.slowPathProcessedCount >= prev.slowPathProcessedCount
                     ? Double(curr.slowPathProcessedCount - prev.slowPathProcessedCount) : 0
            let currDrop = curr.eventBufferDropCount + curr.slowQueueDropCount
            let prevDrop = prev.eventBufferDropCount + prev.slowQueueDropCount
            let drop = currDrop >= prevDrop ? Double(currDrop - prevDrop) : 0

            points.append(ChartPoint(id: "\(key)-hot",  timestamp: t, rate: hot,  series: "Hot path"))
            points.append(ChartPoint(id: "\(key)-slow", timestamp: t, rate: slow, series: "Slow path"))
            points.append(ChartPoint(id: "\(key)-drop", timestamp: t, rate: drop, series: "Drops"))
        }
        return points
    }
}
