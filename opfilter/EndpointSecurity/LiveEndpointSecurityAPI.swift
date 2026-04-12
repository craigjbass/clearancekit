//
//  LiveEndpointSecurityAPI.swift
//  opfilter
//

import EndpointSecurity
import Foundation

// MARK: - LiveEndpointSecurityAPI

struct LiveEndpointSecurityAPI: EndpointSecurityAPI {
    func newClient(handler: @escaping MessageHandler) -> (OpaquePointer?, es_new_client_result_t) {
        var client: OpaquePointer?
        let result = es_new_client(&client) { esClient, message in
            handler(esClient, message)
        }
        return (client, result)
    }

    func deleteClient(_ client: OpaquePointer) {
        es_delete_client(client)
    }

    func subscribe(_ client: OpaquePointer, to events: [es_event_type_t]) -> es_return_t {
        var mutableEvents = events
        return es_subscribe(client, &mutableEvents, UInt32(events.count))
    }

    func respondAuthResult(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>, _ result: es_auth_result_t, _ cacheable: Bool) {
        es_respond_auth_result(client, message, result, cacheable)
    }

    func respondFlagsResult(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>, _ authorizedFlags: UInt32, _ cacheable: Bool) {
        es_respond_flags_result(client, message, authorizedFlags, cacheable)
    }

    func retainMessage(_ message: UnsafePointer<es_message_t>) {
        es_retain_message(message)
    }

    func releaseMessage(_ message: UnsafePointer<es_message_t>) {
        es_release_message(message)
    }

    func mutePath(_ client: OpaquePointer, _ path: String, _ type: es_mute_path_type_t) {
        es_mute_path(client, path, type)
    }

    func unmutePath(_ client: OpaquePointer, _ path: String, _ type: es_mute_path_type_t) {
        es_unmute_path(client, path, type)
    }

    func unmuteAllTargetPaths(_ client: OpaquePointer) {
        es_unmute_all_target_paths(client)
    }

    func invertMuting(_ client: OpaquePointer, _ type: es_mute_inversion_type_t) {
        es_invert_muting(client, type)
    }

    func clearCache(_ client: OpaquePointer) {
        es_clear_cache(client)
    }
}
