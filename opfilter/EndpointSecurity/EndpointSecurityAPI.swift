//
//  EndpointSecurityAPI.swift
//  opfilter
//

import EndpointSecurity
import Foundation

// MARK: - EndpointSecurityAPI

protocol EndpointSecurityAPI {
    typealias MessageHandler = (OpaquePointer, UnsafePointer<es_message_t>) -> Void

    func newClient(handler: @escaping MessageHandler) -> (OpaquePointer?, es_new_client_result_t)
    func deleteClient(_ client: OpaquePointer)
    func subscribe(_ client: OpaquePointer, to events: [es_event_type_t]) -> es_return_t
    func respondAuthResult(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>, _ result: es_auth_result_t, _ cacheable: Bool)
    func respondFlagsResult(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>, _ authorizedFlags: UInt32, _ cacheable: Bool)
    func retainMessage(_ message: UnsafePointer<es_message_t>)
    func releaseMessage(_ message: UnsafePointer<es_message_t>)
    func mutePath(_ client: OpaquePointer, _ path: String, _ type: es_mute_path_type_t)
    func unmutePath(_ client: OpaquePointer, _ path: String, _ type: es_mute_path_type_t)
    func unmuteAllTargetPaths(_ client: OpaquePointer)
    func invertMuting(_ client: OpaquePointer, _ type: es_mute_inversion_type_t)
    func clearCache(_ client: OpaquePointer)
}
