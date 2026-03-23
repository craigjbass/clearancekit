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

    private let interactor: FilterInteractor
    private var client: OpaquePointer?
    private var policyPrefixes: Set<String> = []
    private var discoveryPrefixes: Set<String> = []

    init(interactor: FilterInteractor) {
        self.interactor = interactor
    }

    func start(initialRules: [FAARule], onXProtectChanged: @escaping () -> Void) {
        let interactor = self.interactor
        let res = es_new_client(&client) { (esClient, message) in
            let processName = Self.processName(from: message)
            let pid = pid_t(bitPattern: message.pointee.process.pointee.audit_token.val.5)

            switch message.pointee.event_type {
            case ES_EVENT_TYPE_NOTIFY_WRITE:
                guard Self.isXProtectEvent(message) else { return }
                logger.debug("ES-XPROTECT-WRITE pid=\(pid) process=\(processName, privacy: .public)")
                onXProtectChanged()
            case ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_UNLINK:
                guard !Self.isXProtectEvent(message) else {
                    logger.debug("ES-XPROTECT-MODIFY pid=\(pid) process=\(processName, privacy: .public) type=\(message.pointee.event_type.rawValue) ttdMs=\(Self.millisecondsToDeadline(message.pointee.deadline))")
                    logger.debug("ES-RESPOND pid=\(pid) allowed=true cache=false op=xprotect ttdMs=\(Self.millisecondsToDeadline(message.pointee.deadline))")
                    es_respond_auth_result(esClient, message, ES_AUTH_RESULT_ALLOW, false)
                    onXProtectChanged()
                    return
                }
                Self.dispatchFileAuth(from: message, esClient: esClient, interactor: interactor)
            case ES_EVENT_TYPE_AUTH_OPEN where message.pointee.event.open.file.pointee.path.data == nil:
                logger.debug("ES-OPEN-NIL-PATH pid=\(pid) process=\(processName, privacy: .public) ttdMs=\(Self.millisecondsToDeadline(message.pointee.deadline))")
                logger.debug("ES-RESPOND pid=\(pid) allowed=false cache=false op=open-nil-path ttdMs=\(Self.millisecondsToDeadline(message.pointee.deadline))")
                es_respond_flags_result(esClient, message, UInt32(message.pointee.event.open.fflag), false)
                return
            case ES_EVENT_TYPE_AUTH_EXEC:
                let target = message.pointee.event.exec.target
                let targetPath = Self.string(from: target.pointee.executable.pointee.path)
                logger.debug("ES-EXEC pid=\(pid) process=\(processName, privacy: .public) target=\(targetPath, privacy: .public) ttdMs=\(Self.millisecondsToDeadline(message.pointee.deadline))")
                interactor.handleExec(newImage: processRecord(from: target))
                logger.debug("ES-RESPOND pid=\(pid) allowed=true cache=false op=exec target=\(targetPath, privacy: .public) ttdMs=\(Self.millisecondsToDeadline(message.pointee.deadline))")
                es_respond_auth_result(esClient, message, ES_AUTH_RESULT_ALLOW, false)
            case ES_EVENT_TYPE_NOTIFY_FORK:
                let child = message.pointee.event.fork.child.pointee
                let childPID = pid_t(bitPattern: child.audit_token.val.5)
                let childPath = Self.string(from: child.executable.pointee.path)
                logger.debug("ES-FORK pid=\(pid) process=\(processName, privacy: .public) childPID=\(childPID) childProcess=\(childPath, privacy: .public)")
                interactor.handleFork(child: processRecord(from: message.pointee.event.fork.child))
            case ES_EVENT_TYPE_NOTIFY_EXIT:
                let token = message.pointee.process.pointee.audit_token
                logger.debug("ES-EXIT pid=\(pid) process=\(processName, privacy: .public)")
                interactor.handleExit(identity: ProcessIdentity(pid: pid_t(token.val.5), pidVersion: token.val.7))
            case ES_EVENT_TYPE_AUTH_OPEN,
                 ES_EVENT_TYPE_AUTH_LINK,
                 ES_EVENT_TYPE_AUTH_CREATE,
                 ES_EVENT_TYPE_AUTH_TRUNCATE,
                 ES_EVENT_TYPE_AUTH_COPYFILE,
                 ES_EVENT_TYPE_AUTH_READDIR,
                 ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
                 ES_EVENT_TYPE_AUTH_CLONE:
                Self.dispatchFileAuth(from: message, esClient: esClient, interactor: interactor)
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
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_WRITE,
        ]
        guard es_subscribe(client!, eventTypes, UInt32(eventTypes.count)) == ES_RETURN_SUCCESS else {
            logger.fault("Failed to subscribe to ES events")
            exit(EXIT_FAILURE)
        }

        logger.info("ESInboundAdapter started, monitoring \(initialRules.count) rule prefix(es)")
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
        logger.info("ESInboundAdapter: policy updated — \(rules.count) rule(s), cache cleared")
    }

    /// Temporarily widens monitoring to deliver events for paths with no policy rules.
    /// Pass `["/Users"]` to begin and `[]` to end.
    func setDiscoveryPaths(_ paths: [String]) {
        guard let client else { return }
        let old = policyPrefixes.union(discoveryPrefixes)
        discoveryPrefixes = Set(paths)
        applyPrefixDiff(from: old, to: policyPrefixes.union(discoveryPrefixes), client: client)
        es_clear_cache(client)
        logger.info("ESInboundAdapter: discovery paths updated — \(paths.count) path(s)")
    }

    func clearCache() {
        guard let client else { return }
        es_clear_cache(client)
    }

    private func applyPrefixDiff(from old: Set<String>, to new: Set<String>, client: OpaquePointer) {
        for prefix in old.subtracting(new) {
            es_unmute_path(client, prefix, ES_MUTE_PATH_TYPE_TARGET_PREFIX)
            logger.debug("ESInboundAdapter: removed mute for \(prefix, privacy: .public)")
        }
        for prefix in new.subtracting(old) {
            es_mute_path(client, prefix, ES_MUTE_PATH_TYPE_TARGET_PREFIX)
            logger.debug("ESInboundAdapter: added mute for \(prefix, privacy: .public)")
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

    private static func dispatchFileAuth(from message: UnsafePointer<es_message_t>, esClient: OpaquePointer, interactor: FilterInteractor) {
        let processName = processName(from: message)
        let pid = pid_t(bitPattern: message.pointee.process.pointee.audit_token.val.5)
        let ttdMs = millisecondsToDeadline(message.pointee.deadline)

        switch message.pointee.event_type {
        case ES_EVENT_TYPE_AUTH_OPEN:
            let path = string(from: message.pointee.event.open.file.pointee.path)
            logger.debug("ES-FILE-AUTH pid=\(pid) process=\(processName, privacy: .public) op=open path=\(path, privacy: .public) ttdMs=\(ttdMs)")
            interactor.handleFileAuth(openFileEvent(from: message, esClient: esClient))
        case ES_EVENT_TYPE_AUTH_RENAME:
            let path = string(from: message.pointee.event.rename.source.pointee.path)
            logger.debug("ES-FILE-AUTH pid=\(pid) process=\(processName, privacy: .public) op=rename path=\(path, privacy: .public) ttdMs=\(ttdMs)")
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .rename, path: path))
        case ES_EVENT_TYPE_AUTH_UNLINK:
            let path = string(from: message.pointee.event.unlink.target.pointee.path)
            logger.debug("ES-FILE-AUTH pid=\(pid) process=\(processName, privacy: .public) op=unlink path=\(path, privacy: .public) ttdMs=\(ttdMs)")
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .unlink, path: path))
        case ES_EVENT_TYPE_AUTH_LINK:
            let path = string(from: message.pointee.event.link.source.pointee.path)
            logger.debug("ES-FILE-AUTH pid=\(pid) process=\(processName, privacy: .public) op=link path=\(path, privacy: .public) ttdMs=\(ttdMs)")
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .link, path: path))
        case ES_EVENT_TYPE_AUTH_CREATE:
            let path = createEventPath(from: message.pointee.event.create)
            logger.debug("ES-FILE-AUTH pid=\(pid) process=\(processName, privacy: .public) op=create path=\(path, privacy: .public) ttdMs=\(ttdMs)")
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .create, path: path))
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            let path = string(from: message.pointee.event.truncate.target.pointee.path)
            logger.debug("ES-FILE-AUTH pid=\(pid) process=\(processName, privacy: .public) op=truncate path=\(path, privacy: .public) ttdMs=\(ttdMs)")
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .truncate, path: path))
        case ES_EVENT_TYPE_AUTH_COPYFILE:
            let path = string(from: message.pointee.event.copyfile.source.pointee.path)
            logger.debug("ES-FILE-AUTH pid=\(pid) process=\(processName, privacy: .public) op=copyfile path=\(path, privacy: .public) ttdMs=\(ttdMs)")
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .copyfile, path: path))
        case ES_EVENT_TYPE_AUTH_READDIR:
            let path = string(from: message.pointee.event.readdir.target.pointee.path)
            logger.debug("ES-FILE-AUTH pid=\(pid) process=\(processName, privacy: .public) op=readdir path=\(path, privacy: .public) ttdMs=\(ttdMs)")
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .readdir, path: path))
        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            let path = string(from: message.pointee.event.exchangedata.file1.pointee.path)
            logger.debug("ES-FILE-AUTH pid=\(pid) process=\(processName, privacy: .public) op=exchangedata path=\(path, privacy: .public) ttdMs=\(ttdMs)")
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .exchangedata, path: path))
        case ES_EVENT_TYPE_AUTH_CLONE:
            let path = string(from: message.pointee.event.clone.source.pointee.path)
            logger.debug("ES-FILE-AUTH pid=\(pid) process=\(processName, privacy: .public) op=clone path=\(path, privacy: .public) ttdMs=\(ttdMs)")
            interactor.handleFileAuth(fileAuthEvent(from: message, esClient: esClient, operation: .clone, path: path))
        default:
            fatalError("Received unsubscribed ES event type: \(message.pointee.event_type.rawValue)")
        }
    }

    private static func processName(from message: UnsafePointer<es_message_t>) -> String {
        let fullPath = string(from: message.pointee.process.pointee.executable.pointee.path)
        return URL(fileURLWithPath: fullPath).lastPathComponent
    }

    private static let machTimebase: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    private static func millisecondsToDeadline(_ deadline: UInt64) -> Int64 {
        let now = mach_absolute_time()
        guard deadline > now else { return 0 }
        let ticks = deadline - now
        let nanos = ticks * UInt64(machTimebase.numer) / UInt64(machTimebase.denom)
        return Int64(nanos / 1_000_000)
    }

    static func openFileEvent(from message: UnsafePointer<es_message_t>, esClient: OpaquePointer) -> FileAuthEvent {
        let path = string(from: message.pointee.event.open.file.pointee.path)
        let pid = pid_t(bitPattern: message.pointee.process.pointee.audit_token.val.5)
        let respond: @Sendable (_ allowed: Bool, _ cache: Bool) -> Void = { allowed, cache in
            logger.debug("ES-RESPOND pid=\(pid) allowed=\(allowed) cache=\(cache) op=open path=\(path, privacy: .public) ttdMs=\(millisecondsToDeadline(message.pointee.deadline))")
            es_respond_flags_result(esClient, message, allowed ? UInt32.max : 0, cache)
        }
        return fileAuthEvent(from: message, esClient: esClient, operation: .open, path: path, respond: respond)
    }

    static func fileAuthEvent(
        from message: UnsafePointer<es_message_t>,
        esClient: OpaquePointer,
        operation: FileOperation,
        path: String
    ) -> FileAuthEvent {
        let pid = pid_t(bitPattern: message.pointee.process.pointee.audit_token.val.5)
        let respond: @Sendable (_ allowed: Bool, _ cache: Bool) -> Void = { allowed, cache in
            logger.debug("ES-RESPOND pid=\(pid) allowed=\(allowed) cache=\(cache) op=\(operation.rawValue, privacy: .public) path=\(path, privacy: .public) ttdMs=\(millisecondsToDeadline(message.pointee.deadline))")
            es_respond_auth_result(esClient, message, allowed ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, cache)
        }
        return fileAuthEvent(from: message, esClient: esClient, operation: operation, path: path, respond: respond)
    }

    static func fileAuthEvent(
        from message: UnsafePointer<es_message_t>,
        esClient: OpaquePointer,
        operation: FileOperation,
        path: String,
        respond: @escaping @Sendable (_ allowed: Bool, _ cache: Bool) -> Void
    ) -> FileAuthEvent {
        let process = message.pointee.process.pointee
        let ttyPath: String? = process.tty.map { string(from: $0.pointee.path) }.flatMap { $0.isEmpty ? nil : $0 }
        let processIdentity = ProcessIdentity(
            pid: pid_t(bitPattern: process.audit_token.val.5),
            pidVersion: process.audit_token.val.7
        )
        return FileAuthEvent(
            operation: operation,
            path: path,
            processIdentity: processIdentity,
            processID: processIdentity.pid,
            parentPID: pid_t(bitPattern: process.parent_audit_token.val.5),
            processPath: string(from: process.executable.pointee.path),
            teamID: string(from: process.team_id),
            signingID: string(from: process.signing_id),
            uid: uid_t(process.audit_token.val.1),
            gid: gid_t(process.audit_token.val.2),
            ttyPath: ttyPath,
            deadline: message.pointee.deadline,
            respond: respond
        )
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
