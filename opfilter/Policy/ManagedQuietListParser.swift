//
//  ManagedQuietListParser.swift
//  opfilter
//
//  Plist / mobileconfig schema — entry in the GlobalQuietList array:
//
//    ID             (string, optional)  — stable UUID string; omit to auto-derive
//    SigningID      (string)            — match by signing ID; OR
//    ProcessPath    (string)            — match by executable path
//    PlatformBinary (bool)              — if true, process must be an Apple platform binary
//    TeamID         (string, optional)  — additional team constraint when !PlatformBinary
//

import Foundation

enum ManagedQuietListPreference {
    case absent
    case entries([QuietListEntry])
    case malformed

    func resolved(keeping previous: [QuietListEntry]) -> [QuietListEntry] {
        switch self {
        case .absent:
            return []
        case .entries(let entries):
            return entries
        case .malformed:
            return previous
        }
    }
}

func parseManagedQuietList(_ preferenceValue: Any?) -> ManagedQuietListPreference {
    guard let preferenceValue else { return .absent }
    guard let items = preferenceValue as? [Any] else { return .malformed }
    return .entries(items.compactMap(parseManagedQuietListItem))
}

func parseManagedQuietListEntry(_ dict: [String: Any]) -> QuietListEntry? {
    let signingID   = dict["SigningID"]   as? String ?? ""
    let processPath = dict["ProcessPath"] as? String ?? ""
    guard !signingID.isEmpty || !processPath.isEmpty else {
        NSLog("ManagedQuietListLoader: Skipping entry with no SigningID or ProcessPath")
        return nil
    }

    let platformBinary = dict["PlatformBinary"] as? Bool ?? false
    let teamID = dict["TeamID"] as? String ?? ""

    let id: UUID
    if let idString = dict["ID"] as? String, let parsed = UUID(uuidString: idString) {
        id = parsed
    } else {
        id = uuidV5(namespace: uuidV5URLNamespace, name: signingID.isEmpty ? processPath : signingID)
    }

    return QuietListEntry(
        id: id,
        signingID: signingID,
        processPath: processPath,
        platformBinary: platformBinary,
        teamID: teamID
    )
}

private func parseManagedQuietListItem(_ item: Any) -> QuietListEntry? {
    guard let dict = item as? [String: Any] else {
        NSLog("ManagedQuietListLoader: Skipping GlobalQuietList item that is not a dictionary")
        return nil
    }
    return parseManagedQuietListEntry(dict)
}
