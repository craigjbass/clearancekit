//
//  ProcessTreeProtocol.swift
//  opfilter
//

protocol ProcessTreeProtocol: AnyObject {
    func insert(_ record: ProcessRecord)
    func remove(identity: ProcessIdentity)
    func contains(identity: ProcessIdentity) -> Bool
    func ancestors(of identity: ProcessIdentity) -> [AncestorInfo]
    func allRecords() -> [ProcessRecord]
}
