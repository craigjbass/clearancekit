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
            if xpcClient.metricsHistory.count < 2 {
                waitingPlaceholder
            } else {
                gaugeRow
                throughputChart
                Divider()
                Text("Pipeline throughput — events per second over the last 60 seconds")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding()
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

    private var gaugeRow: some View {
        let s = seriesStats
        return HStack(spacing: 0) {
            rateGauge("Simple events / s",   s.simpleEvents,   .blue)
            rateGauge("Ancestry events / s", s.ancestryEvents, .indigo)
            rateGauge("Drops / s",           s.drops,          .red)
            rateGauge("Jail events / s",     s.jailEvents,     .orange)
            rateGauge("Jail denies / s",     s.jailDenies,     .pink)
        }
    }

    private func rateGauge(_ label: String, _ stats: SeriesStats, _ color: Color) -> some View {
        VStack(spacing: 4) {
            Gauge(value: stats.avg10, in: 0...max(stats.peak, 1)) {
                EmptyView()
            } currentValueLabel: {
                Text(formattedRate(stats.avg10))
                    .font(.system(.caption2, design: .monospaced))
                    .minimumScaleFactor(0.6)
            }
            .gaugeStyle(.accessoryCircular)
            .tint(color)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 2)
        .padding(.top, 8)
        
    }

    private func formattedRate(_ rate: Double) -> String {
        rate >= 100 ? "\(Int(rate.rounded()))" : String(format: "%.1f", rate)
    }

    private var throughputChart: some View {
        Chart(chartData) { point in
            LineMark(
                x: .value("Time", point.timestamp),
                y: .value("Events/s", point.rate)
            )
            .foregroundStyle(by: .value("Series", point.series))
            .interpolationMethod(.monotone)
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

    private struct SeriesStats {
        let avg10: Double
        let peak: Double
    }

    private struct AllSeriesStats {
        let simpleEvents: SeriesStats
        let ancestryEvents: SeriesStats
        let drops: SeriesStats
        let jailEvents: SeriesStats
        let jailDenies: SeriesStats
    }

    private var seriesStats: AllSeriesStats {
        let history = xpcClient.metricsHistory
        guard history.count >= 2 else {
            let zero = SeriesStats(avg10: 0, peak: 0)
            return AllSeriesStats(simpleEvents: zero, ancestryEvents: zero, drops: zero, jailEvents: zero, jailDenies: zero)
        }
        var simple:   [Double] = []
        var ancestry: [Double] = []
        var drops:    [Double] = []
        var jail:     [Double] = []
        var jailDeny: [Double] = []
        for i in 1..<history.count {
            let curr = history[i], prev = history[i - 1]
            simple.append(curr.hotPathProcessedCount  >= prev.hotPathProcessedCount  ? Double(curr.hotPathProcessedCount  - prev.hotPathProcessedCount)  : 0)
            ancestry.append(curr.slowPathProcessedCount >= prev.slowPathProcessedCount ? Double(curr.slowPathProcessedCount - prev.slowPathProcessedCount) : 0)
            let cd = curr.eventBufferDropCount + curr.slowQueueDropCount
            let pd = prev.eventBufferDropCount + prev.slowQueueDropCount
            drops.append(cd >= pd ? Double(cd - pd) : 0)
            jail.append(curr.jailEvaluatedCount >= prev.jailEvaluatedCount ? Double(curr.jailEvaluatedCount - prev.jailEvaluatedCount) : 0)
            jailDeny.append(curr.jailDenyCount  >= prev.jailDenyCount      ? Double(curr.jailDenyCount      - prev.jailDenyCount)      : 0)
        }
        func stats(_ rates: [Double]) -> SeriesStats {
            let window = rates.suffix(10)
            return SeriesStats(
                avg10: window.reduce(0, +) / Double(window.count),
                peak:  rates.max() ?? 0
            )
        }
        return AllSeriesStats(
            simpleEvents:   stats(simple),
            ancestryEvents: stats(ancestry),
            drops:          stats(drops),
            jailEvents:     stats(jail),
            jailDenies:     stats(jailDeny)
        )
    }

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
            let curr = history[i], prev = history[i - 1]
            let t = curr.timestamp
            let key = String(t.timeIntervalSince1970)
            let hot  = curr.hotPathProcessedCount  >= prev.hotPathProcessedCount
                     ? Double(curr.hotPathProcessedCount  - prev.hotPathProcessedCount)  : 0
            let slow = curr.slowPathProcessedCount >= prev.slowPathProcessedCount
                     ? Double(curr.slowPathProcessedCount - prev.slowPathProcessedCount) : 0
            let currDrop = curr.eventBufferDropCount + curr.slowQueueDropCount
            let prevDrop = prev.eventBufferDropCount + prev.slowQueueDropCount
            let drop = currDrop >= prevDrop ? Double(currDrop - prevDrop) : 0
            let jail = curr.jailEvaluatedCount >= prev.jailEvaluatedCount
                     ? Double(curr.jailEvaluatedCount - prev.jailEvaluatedCount) : 0
            let jailDeny = curr.jailDenyCount >= prev.jailDenyCount
                         ? Double(curr.jailDenyCount - prev.jailDenyCount) : 0
            points.append(ChartPoint(id: "\(key)-hot",       timestamp: t, rate: hot,      series: "Simple events"))
            points.append(ChartPoint(id: "\(key)-slow",      timestamp: t, rate: slow,     series: "Ancestry events"))
            points.append(ChartPoint(id: "\(key)-drop",      timestamp: t, rate: drop,     series: "Drops"))
            points.append(ChartPoint(id: "\(key)-jail",      timestamp: t, rate: jail,     series: "Jail events"))
            points.append(ChartPoint(id: "\(key)-jail-deny", timestamp: t, rate: jailDeny, series: "Jail denies"))
        }
        return points
    }
}
