//
//  ESTamperResistanceAdapterTests.swift
//  clearancekitTests
//

import Testing
import EndpointSecurity
import Foundation

@Suite("ESTamperResistanceAdapter")
struct ESTamperResistanceAdapterTests {
    private let ownPID: pid_t = 42
    private let parentPID: pid_t = 1
    private let otherPID: pid_t = 99

    private func makeAdapter() -> (FakeEndpointSecurityAPI, ESTamperResistanceAdapter) {
        let api = FakeEndpointSecurityAPI()
        let adapter = ESTamperResistanceAdapter(ownPID: ownPID, ownParentPID: parentPID, esAPI: api)
        adapter.start()
        return (api, adapter)
    }

    // MARK: - Unknown source targeting own PID

    @Test("unknown source targeting own PID is denied")
    func unknownSourceTargetingOwnPID() {
        let (api, _) = makeAdapter()
        api.simulate(type: ES_EVENT_TYPE_AUTH_SIGNAL, targetPID: ownPID, sourcePID: otherPID)
        #expect(api.lastAuthResult == ES_AUTH_RESULT_DENY)
        #expect(api.lastCacheable == false)
    }

    @Test("unknown source PROC_SUSPEND targeting own PID is denied")
    func unknownSourceSuspendTargetingOwnPID() {
        let (api, _) = makeAdapter()
        api.simulate(type: ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME, targetPID: ownPID, sourcePID: otherPID, suspendResumeType: ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND)
        #expect(api.lastAuthResult == ES_AUTH_RESULT_DENY)
        #expect(api.lastCacheable == false)
    }

    // MARK: - Self source (own PID)

    @Test("self with matching signing is allowed cached")
    func selfSignalSigningPasses() {
        let (api, _) = makeAdapter()
        api.simulate(type: ES_EVENT_TYPE_AUTH_SIGNAL, targetPID: ownPID, sourcePID: ownPID,
                     sourceSigningID: XPCConstants.serviceName, sourceTeamID: XPCConstants.teamID)
        #expect(api.lastAuthResult == ES_AUTH_RESULT_ALLOW)
        #expect(api.lastCacheable == true)
    }

    @Test("self with no signing info is denied")
    func selfSignalSigningFails() {
        let (api, _) = makeAdapter()
        api.simulate(type: ES_EVENT_TYPE_AUTH_SIGNAL, targetPID: ownPID, sourcePID: ownPID)
        #expect(api.lastAuthResult == ES_AUTH_RESULT_DENY)
        #expect(api.lastCacheable == false)
    }

    // MARK: - Parent source (launchd)

    @Test("parent with launchd signing is allowed cached")
    func parentSignalSigningPasses() {
        let (api, _) = makeAdapter()
        api.simulate(type: ES_EVENT_TYPE_AUTH_SIGNAL, targetPID: ownPID, sourcePID: parentPID,
                     sourceSigningID: "com.apple.xpc.launchd", sourceIsPlatformBinary: true)
        #expect(api.lastAuthResult == ES_AUTH_RESULT_ALLOW)
        #expect(api.lastCacheable == true)
    }

    @Test("parent with no signing info is denied")
    func parentSignalSigningFails() {
        let (api, _) = makeAdapter()
        api.simulate(type: ES_EVENT_TYPE_AUTH_SIGNAL, targetPID: ownPID, sourcePID: parentPID)
        #expect(api.lastAuthResult == ES_AUTH_RESULT_DENY)
        #expect(api.lastCacheable == false)
    }

    @Test("parent PROC_SUSPEND with launchd signing is allowed cached")
    func parentSuspendSigningPasses() {
        let (api, _) = makeAdapter()
        api.simulate(type: ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME, targetPID: ownPID, sourcePID: parentPID,
                     sourceSigningID: "com.apple.xpc.launchd", sourceIsPlatformBinary: true,
                     suspendResumeType: ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND)
        #expect(api.lastAuthResult == ES_AUTH_RESULT_ALLOW)
        #expect(api.lastCacheable == true)
    }

    // MARK: - Message lifecycle

    @Test("retain and release are balanced for own PID path")
    func retainReleaseBalancedOwnPID() {
        let (api, _) = makeAdapter()
        api.simulate(type: ES_EVENT_TYPE_AUTH_SIGNAL, targetPID: ownPID, sourcePID: otherPID)
        #expect(api.retainCount == 1)
        #expect(api.releaseCount == 1)
    }

    @Test("retain and release are balanced for other PID path")
    func retainReleaseBalancedOtherPID() {
        let (api, _) = makeAdapter()
        api.simulate(type: ES_EVENT_TYPE_AUTH_SIGNAL, targetPID: otherPID, sourcePID: otherPID)
        #expect(api.retainCount == 1)
        #expect(api.releaseCount == 1)
    }

    // MARK: - Other target (not own PID)

    @Test("signal targeting other PID is allowed cached")
    func signalTargetingOtherPID() {
        let (api, _) = makeAdapter()
        api.simulate(type: ES_EVENT_TYPE_AUTH_SIGNAL, targetPID: otherPID, sourcePID: otherPID)
        #expect(api.lastAuthResult == ES_AUTH_RESULT_ALLOW)
        #expect(api.lastCacheable == true)
    }

    @Test("PROC_SUSPEND targeting other PID is allowed cached")
    func suspendTargetingOtherPID() {
        let (api, _) = makeAdapter()
        api.simulate(type: ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME, targetPID: otherPID, sourcePID: otherPID, suspendResumeType: ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND)
        #expect(api.lastAuthResult == ES_AUTH_RESULT_ALLOW)
        #expect(api.lastCacheable == true)
    }
}

// MARK: - FakeEndpointSecurityAPI

private final class FakeEndpointSecurityAPI: EndpointSecurityAPI {
    // Stable allocation used as the fake ES client handle.
    private static let fakeClientStorage = UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
    private var fakeClient: OpaquePointer { OpaquePointer(Self.fakeClientStorage) }

    private(set) var capturedHandler: MessageHandler?
    private(set) var lastAuthResult: es_auth_result_t?
    private(set) var lastCacheable: Bool?
    private(set) var retainCount = 0
    private(set) var releaseCount = 0

    func newClient(handler: @escaping MessageHandler) -> (OpaquePointer?, es_new_client_result_t) {
        capturedHandler = handler
        return (fakeClient, ES_NEW_CLIENT_RESULT_SUCCESS)
    }

    func subscribe(_ client: OpaquePointer, to events: [es_event_type_t]) -> es_return_t {
        ES_RETURN_SUCCESS
    }

    func respondAuthResult(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>, _ result: es_auth_result_t, _ cacheable: Bool) {
        lastAuthResult = result
        lastCacheable = cacheable
    }

    // MARK: Unused in tamper resistance tests

    func deleteClient(_ client: OpaquePointer) {}
    func respondFlagsResult(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>, _ authorizedFlags: UInt32, _ cacheable: Bool) {}
    func retainMessage(_ message: UnsafePointer<es_message_t>) { retainCount += 1 }
    func releaseMessage(_ message: UnsafePointer<es_message_t>) { releaseCount += 1 }
    func mutePath(_ client: OpaquePointer, _ path: String, _ type: es_mute_path_type_t) {}
    func unmutePath(_ client: OpaquePointer, _ path: String, _ type: es_mute_path_type_t) {}
    func unmuteAllTargetPaths(_ client: OpaquePointer) {}
    func invertMuting(_ client: OpaquePointer, _ type: es_mute_inversion_type_t) {}
    func clearCache(_ client: OpaquePointer) {}

    // MARK: - Event simulation

    /// Synthesises fake es_process_t and es_message_t via zero-filled byte buffers,
    /// sets the required fields, then drives the event through the captured handler.
    /// audit_token.val.5 holds the PID per the macOS ABI (consistent with ESInboundAdapter).
    /// String fields (signing_id, team_id) are kept alive via withUnsafeBufferPointer
    /// wrapping all inner closures so pointers remain valid when the handler fires.
    func simulate(
        type eventType: es_event_type_t,
        targetPID: pid_t,
        sourcePID: pid_t,
        sourceSigningID: String = "",
        sourceTeamID: String = "",
        sourceIsPlatformBinary: Bool = false,
        suspendResumeType: es_proc_suspend_resume_type_t = ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND
    ) {
        guard let capturedHandler else { return }

        let signingIDChars = Array(sourceSigningID.utf8CString)
        let teamIDChars = Array(sourceTeamID.utf8CString)

        signingIDChars.withUnsafeBufferPointer { signingIDBuf in
            teamIDChars.withUnsafeBufferPointer { teamIDBuf in
                var sourceProcessBytes = [UInt8](repeating: 0, count: MemoryLayout<es_process_t>.size)
                var targetProcessBytes = [UInt8](repeating: 0, count: MemoryLayout<es_process_t>.size)
                var messageBytes = [UInt8](repeating: 0, count: MemoryLayout<es_message_t>.size)

                sourceProcessBytes.withUnsafeMutableBytes { rawSource in
                    let sourcePtr = rawSource.assumingMemoryBound(to: es_process_t.self).baseAddress!
                    sourcePtr.pointee.audit_token.val.5 = UInt32(bitPattern: sourcePID)
                    sourcePtr.pointee.is_platform_binary = sourceIsPlatformBinary
                    if !sourceSigningID.isEmpty {
                        sourcePtr.pointee.signing_id = es_string_token_t(length: sourceSigningID.utf8.count, data: signingIDBuf.baseAddress)
                    }
                    if !sourceTeamID.isEmpty {
                        sourcePtr.pointee.team_id = es_string_token_t(length: sourceTeamID.utf8.count, data: teamIDBuf.baseAddress)
                    }

                    targetProcessBytes.withUnsafeMutableBytes { rawTarget in
                        let targetPtr = rawTarget.assumingMemoryBound(to: es_process_t.self).baseAddress!
                        targetPtr.pointee.audit_token.val.5 = UInt32(bitPattern: targetPID)

                        messageBytes.withUnsafeMutableBytes { rawMessage in
                            let messagePtr = rawMessage.assumingMemoryBound(to: es_message_t.self).baseAddress!
                            messagePtr.pointee.event_type = eventType
                            messagePtr.pointee.process = sourcePtr
                            switch eventType {
                            case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
                                messagePtr.pointee.event.proc_suspend_resume.target = targetPtr
                                messagePtr.pointee.event.proc_suspend_resume.type = suspendResumeType
                            case ES_EVENT_TYPE_AUTH_SIGNAL:
                                messagePtr.pointee.event.signal.target = targetPtr
                            default:
                                fatalError("FakeEndpointSecurityAPI.simulate: unsupported event type \(eventType.rawValue)")
                            }
                            capturedHandler(fakeClient, UnsafePointer(messagePtr))
                        }
                    }
                }
            }
        }
    }
}
