//
//  ManagedQuietListLoader.swift
//  opfilter
//
//  Reads the managed GlobalQuietList preference delivered via MDM or a manually
//  installed .mobileconfig profile. Follows the same CFPreferencesCopyAppValue
//  pattern as ManagedAllowlistLoader.
//

import Foundation
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "managed-config")

enum ManagedQuietListLoader {
    private static let preferencesDomain: CFString = XPCConstants.bundleIDPrefix as CFString
    private static let quietListKey: CFString = "GlobalQuietList" as CFString

    static func load() -> ManagedQuietListPreference {
        let preference = parseManagedQuietList(CFPreferencesCopyAppValue(quietListKey, preferencesDomain))
        logLoadedPreference(preference)
        return preference
    }

    static func loadWithSync() -> ManagedQuietListPreference {
        CFPreferencesAppSynchronize(preferencesDomain)
        return load()
    }

    private static func logLoadedPreference(_ preference: ManagedQuietListPreference) {
        switch preference {
        case .absent:
            logger.info("ManagedQuietListLoader: No managed GlobalQuietList found — running without managed quiet list tier")
        case .entries(let entries):
            logger.info("ManagedQuietListLoader: Loaded \(entries.count, privacy: .public) managed quiet list entry/entries")
        case .malformed:
            logger.error("ManagedQuietListLoader: GlobalQuietList is not an array — keeping the previous managed quiet list")
        }
    }
}
