//
//  ProcessEnumerator.swift
//  opfilter
//

import Foundation
import Security

enum ProcessEnumerator {
    static func enumerate(pids: Set<pid_t>) -> [RunningProcessInfo] {
        var result: [RunningProcessInfo] = []
        result.reserveCapacity(pids.count)
        for pid in pids where pid > 0 {
            var bsdInfo = proc_bsdinfo()
            guard proc_pidinfo(
                pid, PROC_PIDTBSDINFO, 0,
                &bsdInfo, Int32(MemoryLayout<proc_bsdinfo>.size)
            ) > 0 else { continue }
            var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            guard proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN)) > 0 else { continue }
            let path = String(cString: pathBuffer)
            guard !path.isEmpty else { continue }
            let (teamID, signingID) = codeSigningIDs(forPID: pid)
            result.append(RunningProcessInfo(
                pid: pid,
                parentPID: Int32(bsdInfo.pbi_ppid),
                path: path,
                teamID: teamID,
                signingID: signingID,
                uid: bsdInfo.pbi_uid
            ))
        }
        return result
    }

    static func enumerateAll() -> [RunningProcessInfo] {
        let estimated = proc_listallpids(nil, 0)
        guard estimated > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(estimated) + 64)
        let count = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size)))
        guard count > 0 else { return [] }

        var result: [RunningProcessInfo] = []
        result.reserveCapacity(count)

        for pid in pids.prefix(count) where pid > 0 {
            var bsdInfo = proc_bsdinfo()
            guard proc_pidinfo(
                pid, PROC_PIDTBSDINFO, 0,
                &bsdInfo, Int32(MemoryLayout<proc_bsdinfo>.size)
            ) > 0 else { continue }

            var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            guard proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN)) > 0 else { continue }
            let path = String(cString: pathBuffer)
            guard !path.isEmpty else { continue }

            let (teamID, signingID) = codeSigningIDs(forPID: pid)

            result.append(RunningProcessInfo(
                pid: pid,
                parentPID: Int32(bsdInfo.pbi_ppid),
                path: path,
                teamID: teamID,
                signingID: signingID,
                uid: bsdInfo.pbi_uid
            ))
        }

        return result
    }

    private static func codeSigningIDs(forPID pid: pid_t) -> (teamID: String, signingID: String) {
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
