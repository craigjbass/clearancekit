//
//  ESProcessRecord.swift
//  opfilter
//

import Foundation
import EndpointSecurity

// MARK: - ProcessRecord from ES event

/// Extracts a ProcessRecord directly from an ES process pointer.
/// All fields are sourced from the ES-provided data; no secondary proc_pidinfo call needed.
func processRecord(from esProcess: UnsafeMutablePointer<es_process_t>) -> ProcessRecord {
    let process = esProcess.pointee
    let identity = ProcessIdentity(
        pid: pid_t(process.audit_token.val.5),
        pidVersion: process.audit_token.val.7
    )
    let parentIdentity = ProcessIdentity(
        pid: pid_t(process.parent_audit_token.val.5),
        pidVersion: process.parent_audit_token.val.7
    )

    let path: String
    if let data = process.executable.pointee.path.data {
        path = String(bytes: Data(bytes: data, count: process.executable.pointee.path.length), encoding: .utf8) ?? ""
    } else {
        path = ""
    }

    let teamID: String
    if let data = process.team_id.data {
        teamID = String(bytes: Data(bytes: data, count: process.team_id.length), encoding: .utf8) ?? ""
    } else {
        teamID = ""
    }

    let signingID: String
    if let data = process.signing_id.data {
        signingID = String(bytes: Data(bytes: data, count: process.signing_id.length), encoding: .utf8) ?? ""
    } else {
        signingID = ""
    }

    let uid = uid_t(process.audit_token.val.1)
    let gid = gid_t(process.audit_token.val.2)

    return ProcessRecord(identity: identity, parentIdentity: parentIdentity, path: path, teamID: teamID, signingID: signingID, uid: uid, gid: gid)
}
