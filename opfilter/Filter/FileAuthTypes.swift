//
//  FileAuthTypes.swift
//  opfilter
//

import Foundation

// MARK: - FileOperation

enum FileOperation: String {
    case open     = "open"
    case rename   = "rename"
    case unlink   = "unlink"
    case link     = "link"
    case create   = "create"
    case truncate = "truncate"
    case copyfile      = "copyfile"
    case readdir       = "readdir"
    case exchangedata  = "exchangedata"
    case clone         = "clone"
}

// MARK: - FileAuthEvent

struct FileAuthEvent: Sendable {
    let correlationID: UUID
    let operation: FileOperation
    let path: String
    let processIdentity: ProcessIdentity
    let processID: pid_t
    let parentPID: pid_t
    let processPath: String
    let teamID: String
    let signingID: String
    let uid: uid_t
    let gid: gid_t
    let ttyPath: String?
    let deadline: UInt64
    let respond: @Sendable (_ allowed: Bool, _ cache: Bool) -> Void
}

// MARK: - MachTime

enum MachTime {
    /// How far before the ES deadline we stop waiting, in nanoseconds.
    static let safetyMarginNanoseconds: UInt64 = 100_000_000 // 100 ms

    /// Timebase ratio, computed once for the process lifetime.
    private static let timebase: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    /// Mach-unit equivalent of `safetyMarginNanoseconds`.
    static let safetyMarginMachUnits: UInt64 = {
        safetyMarginNanoseconds * UInt64(timebase.denom) / UInt64(timebase.numer)
    }()

    static func cutoff(for deadline: UInt64) -> UInt64 {
        guard deadline >= safetyMarginMachUnits else { return 0 }
        return deadline - safetyMarginMachUnits
    }

    static func nanoseconds(from start: UInt64, to end: UInt64) -> UInt64 {
        guard end >= start else { return 0 }
        return (end - start) * UInt64(timebase.numer) / UInt64(timebase.denom)
    }

    static func millisecondsToDeadline(_ deadline: UInt64) -> Int64 {
        let now = mach_absolute_time()
        guard deadline > now else { return 0 }
        let ticks = deadline - now
        let nanos = ticks * UInt64(timebase.numer) / UInt64(timebase.denom)
        return Int64(nanos / 1_000_000)
    }
}

// MARK: - WeakBox

final class WeakBox<T: AnyObject>: @unchecked Sendable {
    weak var value: T?
}
