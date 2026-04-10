//
//  Calendar.swift
//  clearancekit
//

import Foundation

private let calendarGroupContainerSignatures: [ProcessSignature] = [
    apple("com.apple.iCal"),
    apple("com.apple.calaccessd"),
    apple("com.apple.dataaccess.dataaccessd"),
    apple("com.apple.CalendarWeatherKitService"),
]

let calendarPreset = AppPreset(
    id: "calendar-data-protection",
    appName: "Calendar",
    appBundlePath: "/System/Applications/Calendar.app",
    description: "Prevents other processes from reading your Calendar store and account data. Only Calendar, calaccessd, and the calendar sync and weather services may open files in the Calendar data directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-0005-0001-0001-000000000002")!,
            protectedPathPrefix: "/Users/*/Library/Containers/com.apple.iCal",
            allowedSignatures: [apple("com.apple.iCal")]
        ),
        FAARule(
            id: UUID(uuidString: "A1B2C3D4-0005-0001-0001-000000000003")!,
            protectedPathPrefix: "/Users/*/Library/Group Containers/group.com.apple.calendar",
            allowedSignatures: calendarGroupContainerSignatures
        ),
    ]
)
