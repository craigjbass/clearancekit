//
//  CronProtection.swift
//  clearancekit
//

import Foundation

let cronProtectionPreset = AppPreset(
    id: "cron-write-protection",
    appName: "Cron & At Job Protection",
    description: "Prevents malware from scheduling persistent tasks via cron and at. Only the system cron and at daemons may write to scheduling directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "5F0E370E-FE19-4531-8958-DC39D2CEACA9")!,
            protectedPathPrefix: "/private/var/at",
            allowedSignatures: [
                apple("com.apple.atrun"),
                apple("com.apple.cron"),
            ],
            enforceOnWriteOnly: true
        ),
        FAARule(
            id: UUID(uuidString: "EFDA6E88-A410-42FF-AFBE-766D408E9253")!,
            protectedPathPrefix: "/usr/lib/cron",
            allowedSignatures: [apple("com.apple.cron")],
            enforceOnWriteOnly: true
        ),
    ],
    symbolName: "clock.badge.xmark",
    isExperimental: true
)
