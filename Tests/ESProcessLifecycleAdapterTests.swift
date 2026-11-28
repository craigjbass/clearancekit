//
//  ESProcessLifecycleAdapterTests.swift
//  clearancekitTests
//

import Testing
import EndpointSecurity
import Foundation

@Suite("ESProcessLifecycleAdapter")
struct ESProcessLifecycleAdapterTests {
    private func makeAdapter() -> (FakeEndpointSecurityAPI, FakeProcessLifecycleHandler) {
        let api = FakeEndpointSecurityAPI()
        let handler = FakeProcessLifecycleHandler()
        let adapter = ESProcessLifecycleAdapter(esAPI: api, handler: handler)
        adapter.start()
        return (api, handler)
    }

    @Test("subscribes to fork, exec and exit only")
    func subscribesToLifecycleEventsOnly() {
        let (api, _) = makeAdapter()

        #expect(api.subscribedEvents == [
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT,
        ])
    }

    @Test("does not mute or invert muting, so every exec reaches the process tree")
    func doesNotMute() {
        let (api, _) = makeAdapter()

        #expect(api.invertedMuteTypes.isEmpty)
        #expect(api.mutedPaths.isEmpty)
    }

    @Test("exec gives the new image with the target signing identity")
    func execGivesNewImage() {
        let (api, handler) = makeAdapter()

        api.simulateExec(
            source: FakeProcess(pid: 500, pidVersion: 10, path: "/usr/libexec/xpcproxy", signingID: "com.apple.xpc.proxy", isPlatformBinary: true),
            target: FakeProcess(pid: 500, pidVersion: 11, parentPID: 1, parentPIDVersion: 2, path: "/Applications/Safari.app/Contents/MacOS/Safari", signingID: "com.apple.Safari", isPlatformBinary: true)
        )

        let newImage = handler.execs.first
        #expect(handler.execs.count == 1)
        #expect(newImage?.identity == ProcessIdentity(pid: 500, pidVersion: 11))
        #expect(newImage?.parentIdentity == ProcessIdentity(pid: 1, pidVersion: 2))
        #expect(newImage?.path == "/Applications/Safari.app/Contents/MacOS/Safari")
        #expect(newImage?.signingID == "com.apple.Safari")
        #expect(newImage?.teamID == "apple")
    }

    @Test("fork gives the child record")
    func forkGivesChild() {
        let (api, handler) = makeAdapter()

        api.simulateFork(
            parent: FakeProcess(pid: 1, pidVersion: 2, path: "/sbin/launchd", signingID: "com.apple.xpc.launchd", isPlatformBinary: true),
            child: FakeProcess(pid: 600, pidVersion: 20, parentPID: 1, parentPIDVersion: 2, path: "/sbin/launchd", signingID: "com.apple.xpc.launchd", isPlatformBinary: true)
        )

        #expect(handler.forks.map(\.identity) == [ProcessIdentity(pid: 600, pidVersion: 20)])
    }

    @Test("exit gives the exiting process identity")
    func exitGivesIdentity() {
        let (api, handler) = makeAdapter()

        api.simulateExit(process: FakeProcess(pid: 700, pidVersion: 30, path: "/bin/ls", signingID: "com.apple.ls", isPlatformBinary: true))

        #expect(handler.exits == [ProcessIdentity(pid: 700, pidVersion: 30)])
    }
}

// MARK: - FakeProcessLifecycleHandler

private final class FakeProcessLifecycleHandler: ProcessLifecycleHandler {
    private(set) var forks: [ProcessRecord] = []
    private(set) var execs: [ProcessRecord] = []
    private(set) var exits: [ProcessIdentity] = []

    func handleFork(child: ProcessRecord) { forks.append(child) }
    func handleExec(newImage: ProcessRecord) { execs.append(newImage) }
    func handleExit(identity: ProcessIdentity) { exits.append(identity) }
}

// MARK: - FakeProcess

private struct FakeProcess {
    let pid: pid_t
    let pidVersion: UInt32
    var parentPID: pid_t = 0
    var parentPIDVersion: UInt32 = 0
    let path: String
    let signingID: String
    let isPlatformBinary: Bool
}

// MARK: - FakeEndpointSecurityAPI

private final class FakeEndpointSecurityAPI: EndpointSecurityAPI {
    // Stable allocation used as the fake ES client handle.
    private static let fakeClientStorage = UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
    private var fakeClient: OpaquePointer { OpaquePointer(Self.fakeClientStorage) }

    private var capturedHandler: MessageHandler?
    private(set) var subscribedEvents: [es_event_type_t] = []
    private(set) var invertedMuteTypes: [es_mute_inversion_type_t] = []
    private(set) var mutedPaths: [String] = []

    func newClient(handler: @escaping MessageHandler) -> (OpaquePointer?, es_new_client_result_t) {
        capturedHandler = handler
        return (fakeClient, ES_NEW_CLIENT_RESULT_SUCCESS)
    }

    func subscribe(_ client: OpaquePointer, to events: [es_event_type_t]) -> es_return_t {
        subscribedEvents.append(contentsOf: events)
        return ES_RETURN_SUCCESS
    }

    func invertMuting(_ client: OpaquePointer, _ type: es_mute_inversion_type_t) {
        invertedMuteTypes.append(type)
    }

    func mutePath(_ client: OpaquePointer, _ path: String, _ type: es_mute_path_type_t) {
        mutedPaths.append(path)
    }

    // MARK: Unused in process lifecycle tests

    func deleteClient(_ client: OpaquePointer) {}
    func respondAuthResult(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>, _ result: es_auth_result_t, _ cacheable: Bool) {}
    func respondFlagsResult(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>, _ authorizedFlags: UInt32, _ cacheable: Bool) {}
    func retainMessage(_ message: UnsafePointer<es_message_t>) {}
    func releaseMessage(_ message: UnsafePointer<es_message_t>) {}
    func unmutePath(_ client: OpaquePointer, _ path: String, _ type: es_mute_path_type_t) {}
    func unmuteAllTargetPaths(_ client: OpaquePointer) {}
    func clearCache(_ client: OpaquePointer) {}

    // MARK: - Event simulation

    func simulateExec(source: FakeProcess, target: FakeProcess) {
        withProcess(source) { sourcePointer in
            withProcess(target) { targetPointer in
                deliver(ES_EVENT_TYPE_NOTIFY_EXEC, process: sourcePointer) { message in
                    message.pointee.event.exec.target = targetPointer
                }
            }
        }
    }

    func simulateFork(parent: FakeProcess, child: FakeProcess) {
        withProcess(parent) { parentPointer in
            withProcess(child) { childPointer in
                deliver(ES_EVENT_TYPE_NOTIFY_FORK, process: parentPointer) { message in
                    message.pointee.event.fork.child = childPointer
                }
            }
        }
    }

    func simulateExit(process: FakeProcess) {
        withProcess(process) { processPointer in
            deliver(ES_EVENT_TYPE_NOTIFY_EXIT, process: processPointer) { _ in }
        }
    }

    private func deliver(
        _ eventType: es_event_type_t,
        process: UnsafeMutablePointer<es_process_t>,
        setEvent: (UnsafeMutablePointer<es_message_t>) -> Void
    ) {
        guard let capturedHandler else { return }
        var messageBytes = [UInt8](repeating: 0, count: MemoryLayout<es_message_t>.size)
        messageBytes.withUnsafeMutableBytes { rawMessage in
            let message = rawMessage.assumingMemoryBound(to: es_message_t.self).baseAddress!
            message.pointee.event_type = eventType
            message.pointee.process = process
            setEvent(message)
            capturedHandler(fakeClient, UnsafePointer(message))
        }
    }

    /// Builds a zero-filled es_process_t with its es_file_t and string tokens.
    /// The pointers stay valid only inside `body`.
    private func withProcess(_ fake: FakeProcess, body: (UnsafeMutablePointer<es_process_t>) -> Void) {
        let pathChars = Array(fake.path.utf8CString)
        let signingIDChars = Array(fake.signingID.utf8CString)
        pathChars.withUnsafeBufferPointer { pathBuffer in
            signingIDChars.withUnsafeBufferPointer { signingIDBuffer in
                var fileBytes = [UInt8](repeating: 0, count: MemoryLayout<es_file_t>.size)
                var processBytes = [UInt8](repeating: 0, count: MemoryLayout<es_process_t>.size)
                fileBytes.withUnsafeMutableBytes { rawFile in
                    let file = rawFile.assumingMemoryBound(to: es_file_t.self).baseAddress!
                    file.pointee.path = es_string_token_t(length: fake.path.utf8.count, data: pathBuffer.baseAddress)
                    processBytes.withUnsafeMutableBytes { rawProcess in
                        let process = rawProcess.assumingMemoryBound(to: es_process_t.self).baseAddress!
                        process.pointee.audit_token.val.5 = UInt32(bitPattern: fake.pid)
                        process.pointee.audit_token.val.7 = fake.pidVersion
                        process.pointee.parent_audit_token.val.5 = UInt32(bitPattern: fake.parentPID)
                        process.pointee.parent_audit_token.val.7 = fake.parentPIDVersion
                        process.pointee.executable = file
                        process.pointee.is_platform_binary = fake.isPlatformBinary
                        process.pointee.signing_id = es_string_token_t(length: fake.signingID.utf8.count, data: signingIDBuffer.baseAddress)
                        body(process)
                    }
                }
            }
        }
    }
}
