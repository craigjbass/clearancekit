//
//  ESInboundAdapter.swift
//  opfilter
//

import Foundation
import EndpointSecurity
import os

private let logger = Logger(subsystem: "uk.craigbass.clearancekit.opfilter", category: "es-adapter")


final class ESInboundAdapter {
    static let xprotectPath = "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS"

    private let interactor: FAAFilterInteractor
    private let esAdapterQueue: DispatchQueue
    private var client: OpaquePointer?
    private var policyPrefixes: Set<String> = []
    private var discoveryPrefixes: Set<String> = []

    init(
        interactor: FAAFilterInteractor,
        esAdapterQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.es-adapter", qos: .userInteractive, autoreleaseFrequency: .never)
    ) {
        self.interactor = interactor
        self.esAdapterQueue = esAdapterQueue
    }

    func start(initialRules: [FAARule], onXProtectChanged: @escaping () -> Void) {
        let interactor = self.interactor
        let esAdapterQueue = self.esAdapterQueue
        let res = es_new_client(&client) { (esClient, message) in
            let correlationID = UUID()

            switch message.pointee.event_type {
            case ES_EVENT_TYPE_NOTIFY_WRITE:
                let isXProtect = Self.isXProtectEvent(message)
                esAdapterQueue.async {
                    guard isXProtect else { return }
                    onXProtectChanged()
                }
            case ES_EVENT_TYPE_NOTIFY_EXEC:
                let record = processRecord(from: message.pointee.event.exec.target)
                esAdapterQueue.async { interactor.handleExec(newImage: record) }
            case ES_EVENT_TYPE_NOTIFY_FORK:
                let child = processRecord(from: message.pointee.event.fork.child)
                esAdapterQueue.async { interactor.handleFork(child: child) }
            case ES_EVENT_TYPE_NOTIFY_EXIT:
                let token = message.pointee.process.pointee.audit_token
                let identity = ProcessIdentity(pid: pid_t(token.val.5), pidVersion: token.val.7)
                esAdapterQueue.async { interactor.handleExit(identity: identity) }
            case ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_UNLINK:
                es_retain_message(message)
                esAdapterQueue.async {
                    guard !Self.isXProtectEvent(message) else {
                        es_respond_auth_result(esClient, message, ES_AUTH_RESULT_ALLOW, false)
                        es_release_message(message)
                        onXProtectChanged()
                        return
                    }
                    Self.dispatchFileAuth(from: message, esClient: esClient, interactor: interactor, correlationID: correlationID)
                }
            case ES_EVENT_TYPE_AUTH_OPEN where message.pointee.event.open.file.pointee.path.data == nil:
                es_retain_message(message)
                esAdapterQueue.async {
                    logger.error("Path invariant not met. Got nil path.")
                    es_respond_flags_result(esClient, message, UInt32(message.pointee.event.open.fflag), false)
                    es_release_message(message)
                }
            case ES_EVENT_TYPE_AUTH_OPEN,
                 ES_EVENT_TYPE_AUTH_LINK,
                 ES_EVENT_TYPE_AUTH_CREATE,
                 ES_EVENT_TYPE_AUTH_TRUNCATE,
                 ES_EVENT_TYPE_AUTH_COPYFILE,
                 ES_EVENT_TYPE_AUTH_READDIR,
                 ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
                 ES_EVENT_TYPE_AUTH_CLONE:
                es_retain_message(message)
                esAdapterQueue.async {
                    Self.dispatchFileAuth(from: message, esClient: esClient, interactor: interactor, correlationID: correlationID)
                }
            default:
                fatalError("ESInboundAdapter: received unsubscribed event type \(message.pointee.event_type.rawValue)")
            }
        }

        guard res == ES_NEW_CLIENT_RESULT_SUCCESS else {
            logger.fault("Failed to create ES client: \(res.rawValue)")
            exit(EXIT_FAILURE)
        }

        // Invert target-path muting so only muted prefixes generate events.
        // We then mute exactly the protected path prefixes from the active policy,
        // so the kernel delivers events only for files we actually care about.
        es_unmute_all_target_paths(client!)
        es_invert_muting(client!, ES_MUTE_INVERSION_TYPE_TARGET_PATH)
        applyMutedPrefixes(from: initialRules)

        let eventTypes: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_LINK,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_TRUNCATE,
            ES_EVENT_TYPE_AUTH_COPYFILE,
            ES_EVENT_TYPE_AUTH_READDIR,
            ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
            ES_EVENT_TYPE_AUTH_CLONE,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_WRITE,
        ]
        guard es_subscribe(client!, eventTypes, UInt32(eventTypes.count)) == ES_RETURN_SUCCESS else {
            logger.fault("Failed to subscribe to ES events")
            exit(EXIT_FAILURE)
        }
    }

    /// Applies an updated policy: diffs the effective muted prefix set (policy ∪ discovery),
    /// clears the ES authorization cache, and updates the interactor's rule set.
    func updatePolicy(_ rules: [FAARule]) {
        guard let client else { return }
        let old = policyPrefixes.union(discoveryPrefixes)
        policyPrefixes = Set(rules.map { mutePath(for: $0.protectedPathPrefix) })
        applyPrefixDiff(from: old, to: policyPrefixes.union(discoveryPrefixes), client: client)
        es_clear_cache(client)
        interactor.updatePolicy(rules)
    }

    /// Temporarily widens monitoring to deliver events for paths with no policy rules.
    /// Pass `["/Users"]` to begin and `[]` to end.
    func setDiscoveryPaths(_ paths: [String]) {
        guard let client else { return }
        let old = policyPrefixes.union(discoveryPrefixes)
        discoveryPrefixes = Set(paths)
        applyPrefixDiff(from: old, to: policyPrefixes.union(discoveryPrefixes), client: client)
        es_clear_cache(client)
    }

    func clearCache() {
        guard let client else { return }
        es_clear_cache(client)
    }

    private func applyPrefixDiff(from old: Set<String>, to new: Set<String>, client: OpaquePointer) {
        for prefix in old.subtracting(new) {
            es_unmute_path(client, prefix, ES_MUTE_PATH_TYPE_TARGET_PREFIX)
        }
        for prefix in new.subtracting(old) {
            es_mute_path(client, prefix, ES_MUTE_PATH_TYPE_TARGET_PREFIX)
        }
    }

    private func applyMutedPrefixes(from rules: [FAARule]) {
        guard let client else { return }
        policyPrefixes = Set(rules.map { mutePath(for: $0.protectedPathPrefix) })
        for prefix in policyPrefixes {
            es_mute_path(client, prefix, ES_MUTE_PATH_TYPE_TARGET_PREFIX)
        }
        // XProtect path is permanently muted so NOTIFY_WRITE, AUTH_RENAME, and AUTH_UNLINK events
        // are always delivered for it. Kept outside policyPrefixes so policy diffs never unmute it.
        es_mute_path(client, Self.xprotectPath, ES_MUTE_PATH_TYPE_TARGET_PREFIX)
    }

    private static func isXProtectEvent(_ message: UnsafePointer<es_message_t>) -> Bool {
        let token: es_string_token_t
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            token = message.pointee.event.write.target.pointee.path
        case ES_EVENT_TYPE_AUTH_RENAME:
            token = message.pointee.event.rename.source.pointee.path
        case ES_EVENT_TYPE_AUTH_UNLINK:
            token = message.pointee.event.unlink.target.pointee.path
        default:
            return false
        }
        return string(from: token).hasPrefix(xprotectPath)
    }

    private static func dispatchFileAuth(from message: UnsafePointer<es_message_t>, esClient: OpaquePointer, interactor: FAAFilterInteractor, correlationID: UUID) {
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_AUTH_OPEN:
            interactor.handleFileAuth(openFileEvent(from: message, esClient: esClient, correlationID: correlationID))
        case ES_EVENT_TYPE_AUTH_RENAME:
            let path = string(from: message.pointee.event.rename.source.pointee.path)
            let secondaryPath = renameDestinationPath(from: message.pointee.event.rename)
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .rename, path: path, secondaryPath: secondaryPath, correlationID: correlationID))
        case ES_EVENT_TYPE_AUTH_UNLINK:
            let path = string(from: message.pointee.event.unlink.target.pointee.path)
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .unlink, path: path, correlationID: correlationID))
        case ES_EVENT_TYPE_AUTH_LINK:
            let path = string(from: message.pointee.event.link.source.pointee.path)
            let secondaryPath = linkDestinationPath(from: message.pointee.event.link)
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .link, path: path, secondaryPath: secondaryPath, correlationID: correlationID))
        case ES_EVENT_TYPE_AUTH_CREATE:
            let path = createEventPath(from: message.pointee.event.create)
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .create, path: path, correlationID: correlationID))
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            let path = string(from: message.pointee.event.truncate.target.pointee.path)
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .truncate, path: path, correlationID: correlationID))
        case ES_EVENT_TYPE_AUTH_COPYFILE:
            let path = string(from: message.pointee.event.copyfile.source.pointee.path)
            let secondaryPath = copyfileDestinationPath(from: message.pointee.event.copyfile)
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .copyfile, path: path, secondaryPath: secondaryPath, correlationID: correlationID))
        case ES_EVENT_TYPE_AUTH_READDIR:
            let path = string(from: message.pointee.event.readdir.target.pointee.path)
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .readdir, path: path, correlationID: correlationID))
        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            let path = string(from: message.pointee.event.exchangedata.file1.pointee.path)
            let secondaryPath = string(from: message.pointee.event.exchangedata.file2.pointee.path)
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .exchangedata, path: path, secondaryPath: secondaryPath, correlationID: correlationID))
        case ES_EVENT_TYPE_AUTH_CLONE:
            let path = string(from: message.pointee.event.clone.source.pointee.path)
            let secondaryPath = cloneDestinationPath(from: message.pointee.event.clone)
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .clone, path: path, secondaryPath: secondaryPath, correlationID: correlationID))
        default:
            fatalError("Received unsubscribed ES event type: \(message.pointee.event_type.rawValue)")
        }
    }

    static func openFileEvent(from message: UnsafePointer<es_message_t>, esClient: OpaquePointer, correlationID: UUID = UUID()) -> FileAuthEvent {
        let path = string(from: message.pointee.event.open.file.pointee.path)
        let respond: @Sendable (_ allowed: Bool, _ cache: Bool) -> Void = { allowed, cache in
            es_respond_flags_result(esClient, message, allowed ? UInt32.max : 0, cache)
            es_release_message(message)
        }
        return fileAuthEvent(from: message, esClient: esClient, operation: .open, path: path, secondaryPath: nil, correlationID: correlationID, respond: respond)
    }

    static func fileAuthEvent(
        from message: UnsafePointer<es_message_t>,
        esClient: OpaquePointer,
        operation: FileOperation,
        path: String,
        secondaryPath: String? = nil,
        correlationID: UUID = UUID()
    ) -> FileAuthEvent {
        let respond: @Sendable (_ allowed: Bool, _ cache: Bool) -> Void = { allowed, cache in
            es_respond_auth_result(esClient, message, allowed ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, cache)
            es_release_message(message)
        }
        return fileAuthEvent(from: message, esClient: esClient, operation: operation, path: path, secondaryPath: secondaryPath, correlationID: correlationID, respond: respond)
    }

    private static func fileAuthEvent(
        from message: UnsafePointer<es_message_t>,
        esClient: OpaquePointer,
        operation: FileOperation,
        path: String,
        secondaryPath: String?,
        correlationID: UUID,
        respond: @escaping @Sendable (_ allowed: Bool, _ cache: Bool) -> Void
    ) -> FileAuthEvent {
        let process = message.pointee.process.pointee
        let ttyPath: String? = process.tty.map { string(from: $0.pointee.path) }.flatMap { $0.isEmpty ? nil : $0 }
        let processIdentity = ProcessIdentity(
            pid: pid_t(bitPattern: process.audit_token.val.5),
            pidVersion: process.audit_token.val.7
        )
        let signingID = string(from: process.signing_id)
        let rawTeamID = string(from: process.team_id)
        let teamID = rawTeamID.isEmpty && !signingID.isEmpty ? "apple" : rawTeamID
        return FileAuthEvent(
            correlationID: correlationID,
            operation: operation,
            path: path,
            secondaryPath: secondaryPath,
            processIdentity: processIdentity,
            processID: processIdentity.pid,
            parentPID: pid_t(bitPattern: process.parent_audit_token.val.5),
            processPath: string(from: process.executable.pointee.path),
            teamID: teamID,
            signingID: signingID,
            uid: uid_t(process.audit_token.val.1),
            gid: gid_t(process.audit_token.val.2),
            ttyPath: ttyPath,
            deadline: message.pointee.deadline,
            respond: respond
        )
    }

    static func renameDestinationPath(from event: es_event_rename_t) -> String {
        switch event.destination_type {
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            return string(from: event.destination.existing_file.pointee.path)
        case ES_DESTINATION_TYPE_NEW_PATH:
            let dir = string(from: event.destination.new_path.dir.pointee.path)
            let filename = string(from: event.destination.new_path.filename)
            return "\(dir)/\(filename)"
        default:
            return ""
        }
    }

    static func linkDestinationPath(from event: es_event_link_t) -> String {
        let dir = string(from: event.target_dir.pointee.path)
        let filename = string(from: event.target_filename)
        return "\(dir)/\(filename)"
    }

    static func copyfileDestinationPath(from event: es_event_copyfile_t) -> String {
        let dir = string(from: event.target_dir.pointee.path)
        let filename = string(from: event.target_name)
        return "\(dir)/\(filename)"
    }

    static func cloneDestinationPath(from event: es_event_clone_t) -> String {
        let dir = string(from: event.target_dir.pointee.path)
        let filename = string(from: event.target_name)
        return "\(dir)/\(filename)"
    }

    static func createEventPath(from event: es_event_create_t) -> String {
        switch event.destination_type {
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            return string(from: event.destination.existing_file.pointee.path)
        case ES_DESTINATION_TYPE_NEW_PATH:
            let dir = string(from: event.destination.new_path.dir.pointee.path)
            let filename = string(from: event.destination.new_path.filename)
            return "\(dir)/\(filename)"
        default:
            return ""
        }
    }

    static func string(from esString: es_string_token_t) -> String {
        guard let data = esString.data else { return "" }
        return String(bytes: Data(bytes: data, count: esString.length), encoding: .utf8) ?? ""
    }
}
