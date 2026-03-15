//
//  DaemonXPCServer.swift
//  clearancekit-daemon
//

import Foundation

private let userPolicyDir        = URL(fileURLWithPath: "/Library/Application Support/clearancekit")
private let userPolicyURL        = userPolicyDir.appendingPathComponent("user-policy.json")
private let signatureURL         = userPolicyDir.appendingPathComponent("user-policy.json.sig")
private let allowlistURL         = userPolicyDir.appendingPathComponent("global-allowlist.json")
private let allowlistSignatureURL = userPolicyDir.appendingPathComponent("global-allowlist.json.sig")

final class DaemonXPCServer: NSObject {
    static let shared = DaemonXPCServer()

    private var listener: NSXPCListener?
    private let lock = NSLock()
    private var guiClients: [ObjectIdentifier: NSXPCConnection] = [:]
    private var filterClients: [ObjectIdentifier: NSXPCConnection] = [:]
    private var monitoringActive = false
    private var recentEvents: [FolderOpenEvent] = []
    private var managedRules: [FAARule] = []
    private var userRules: [FAARule] = []
    private var managedAllowlist: [AllowlistEntry] = []
    private var userAllowlist: [AllowlistEntry] = []
    private let maxHistoryCount = 1000

    private override init() {
        super.init()
    }

    func start() {
        userRules = loadUserRulesFromDisk()
        managedRules = ManagedPolicyLoader.load()
        userAllowlist = loadUserAllowlistFromDisk()
        managedAllowlist = ManagedAllowlistLoader.load()
        // Both rule tiers must be loaded before the listener resumes so that
        // mergedPolicyData() is complete the moment the first filter client connects.
        listener = NSXPCListener(machServiceName: XPCConstants.daemonServiceName)
        listener?.delegate = self
        listener?.resume()
        NSLog("DaemonXPCServer: Listening on %@", XPCConstants.daemonServiceName)
    }

    // MARK: - Client registration

    fileprivate func addGUIClient(_ connection: NSXPCConnection) {
        lock.lock()
        guiClients[ObjectIdentifier(connection)] = connection
        let count = guiClients.count
        lock.unlock()
        NSLog("DaemonXPCServer: GUI client registered. Active clients: %d", count)
    }

    fileprivate func addFilterClient(_ connection: NSXPCConnection) {
        lock.lock()
        filterClients[ObjectIdentifier(connection)] = connection
        let count = filterClients.count
        lock.unlock()
        NSLog("DaemonXPCServer: Filter client registered. Active filter clients: %d", count)
        // Push current merged policy and allowlist immediately so the filter is up to date on connect/reconnect.
        (connection.remoteObjectProxy as? FilterClientProtocol)?.policyUpdated(mergedPolicyData())
        (connection.remoteObjectProxy as? FilterClientProtocol)?.allowlistUpdated(mergedAllowlistData())
    }

    fileprivate func removeClient(_ connection: NSXPCConnection) {
        lock.lock()
        guiClients.removeValue(forKey: ObjectIdentifier(connection))
        filterClients.removeValue(forKey: ObjectIdentifier(connection))
        let guiCount = guiClients.count
        let filterCount = filterClients.count
        lock.unlock()
        NSLog("DaemonXPCServer: Client removed. GUI: %d, Filter: %d", guiCount, filterCount)
    }

    // MARK: - Event broadcasting

    fileprivate func broadcastEvent(_ event: FolderOpenEvent) {
        lock.lock()
        recentEvents.append(event)
        if recentEvents.count > maxHistoryCount {
            recentEvents.removeFirst(recentEvents.count - maxHistoryCount)
        }
        let clients = Array(guiClients.values)
        lock.unlock()
        for conn in clients {
            (conn.remoteObjectProxy as? DaemonClientProtocol)?.folderOpened(event)
        }
    }

    fileprivate func getRecentEvents() -> [FolderOpenEvent] {
        lock.lock()
        defer { lock.unlock() }
        return recentEvents
    }

    fileprivate func broadcastMonitoringStatus(_ isActive: Bool) {
        monitoringActive = isActive
        lock.lock()
        let clients = Array(guiClients.values)
        lock.unlock()
        for conn in clients {
            (conn.remoteObjectProxy as? DaemonClientProtocol)?.monitoringStatusChanged(isActive)
        }
    }

    fileprivate func currentMonitoringStatus() -> Bool {
        monitoringActive
    }

    // MARK: - Rule mutations

    fileprivate func applyAddRule(_ rule: FAARule) {
        lock.lock()
        userRules.append(rule)
        lock.unlock()
        persistAndBroadcast()
    }

    fileprivate func applyUpdateRule(_ rule: FAARule) {
        lock.lock()
        guard let index = userRules.firstIndex(where: { $0.id == rule.id }) else {
            lock.unlock()
            NSLog("DaemonXPCServer: updateRule — rule %@ not found", rule.id.uuidString)
            return
        }
        userRules[index] = rule
        lock.unlock()
        persistAndBroadcast()
    }

    fileprivate func applyRemoveRule(ruleID: UUID) {
        lock.lock()
        userRules.removeAll { $0.id == ruleID }
        lock.unlock()
        persistAndBroadcast()
    }

    private func persistAndBroadcast() {
        saveUserRulesToDisk()
        broadcastMergedPolicyToFilterClients()
        broadcastUserRulesToAllGUIClients()
    }

    // MARK: - Resync

    fileprivate func requestResyncFromFilterClients(requestingConnection: NSXPCConnection) {
        // Reload managed rules and allowlist — picks up any MDM profile changes since last resync.
        let reloaded = ManagedPolicyLoader.loadWithSync()
        let reloadedAllowlist = ManagedAllowlistLoader.loadWithSync()
        lock.lock()
        managedRules = reloaded
        managedAllowlist = reloadedAllowlist
        lock.unlock()

        // Re-broadcast merged policy and allowlist to filter clients.
        broadcastMergedPolicyToFilterClients()
        broadcastMergedAllowlistToFilterClients()

        lock.lock()
        let clients = Array(filterClients.values)
        lock.unlock()
        NSLog("DaemonXPCServer: Requesting resync from %d filter client(s)", clients.count)
        for conn in clients {
            (conn.remoteObjectProxy as? FilterClientProtocol)?.resyncStatus()
        }

        pushPolicySnapshotToGUIClient(requestingConnection)
    }

    // MARK: - Policy helpers

    fileprivate func mergedPolicyData() -> NSData {
        // Evaluation order: baseline → managed → user. First match wins, so higher
        // tiers always take precedence for any overlapping path prefix.
        lock.lock()
        let managed = managedRules
        let user = userRules
        lock.unlock()
        guard let data = try? JSONEncoder().encode(faaPolicy + managed + user) else {
            fatalError("DaemonXPCServer: Failed to encode merged policy — this is a bug")
        }
        return data as NSData
    }

    private func encodedManagedRules() -> NSData {
        lock.lock()
        let rules = managedRules
        lock.unlock()
        guard let data = try? JSONEncoder().encode(rules) else {
            fatalError("DaemonXPCServer: Failed to encode managed rules — this is a bug")
        }
        return data as NSData
    }

    private func encodedUserRules() -> NSData {
        lock.lock()
        let rules = userRules
        lock.unlock()
        guard let data = try? JSONEncoder().encode(rules) else {
            fatalError("DaemonXPCServer: Failed to encode user rules — this is a bug")
        }
        return data as NSData
    }

    private func broadcastMergedPolicyToFilterClients() {
        let data = mergedPolicyData()
        lock.lock()
        let clients = Array(filterClients.values)
        lock.unlock()
        NSLog("DaemonXPCServer: Broadcasting merged policy to %d filter client(s)", clients.count)
        for conn in clients {
            (conn.remoteObjectProxy as? FilterClientProtocol)?.policyUpdated(data)
        }
    }

    private func broadcastUserRulesToAllGUIClients() {
        let data = encodedUserRules()
        lock.lock()
        let clients = Array(guiClients.values)
        lock.unlock()
        for conn in clients {
            (conn.remoteObjectProxy as? DaemonClientProtocol)?.userRulesUpdated(data)
        }
    }

    /// Pushes the managed- and user-rule snapshots to a single GUI client.
    /// Called on connect (via requestResync) so the GUI always has a complete
    /// picture of both editable tiers immediately after connecting.
    fileprivate func pushPolicySnapshotToGUIClient(_ connection: NSXPCConnection) {
        let proxy = connection.remoteObjectProxy as? DaemonClientProtocol
        proxy?.managedRulesUpdated(encodedManagedRules())
        proxy?.userRulesUpdated(encodedUserRules())
        proxy?.managedAllowlistUpdated(encodedManagedAllowlist())
        proxy?.userAllowlistUpdated(encodedUserAllowlist())
    }

    // MARK: - Allowlist mutations

    fileprivate func applyAddAllowlistEntry(_ entry: AllowlistEntry) {
        lock.lock()
        userAllowlist.append(entry)
        lock.unlock()
        persistAndBroadcastAllowlist()
    }

    fileprivate func applyRemoveAllowlistEntry(entryID: UUID) {
        lock.lock()
        userAllowlist.removeAll { $0.id == entryID }
        lock.unlock()
        persistAndBroadcastAllowlist()
    }

    private func persistAndBroadcastAllowlist() {
        saveUserAllowlistToDisk()
        broadcastMergedAllowlistToFilterClients()
        broadcastUserAllowlistToAllGUIClients()
    }

    // MARK: - Allowlist helpers

    fileprivate func mergedAllowlistData() -> NSData {
        lock.lock()
        let managed = managedAllowlist
        let user = userAllowlist
        lock.unlock()
        guard let data = try? JSONEncoder().encode(baselineAllowlist + managed + user) else {
            fatalError("DaemonXPCServer: Failed to encode merged allowlist — this is a bug")
        }
        return data as NSData
    }

    private func encodedManagedAllowlist() -> NSData {
        lock.lock()
        let entries = managedAllowlist
        lock.unlock()
        guard let data = try? JSONEncoder().encode(entries) else {
            fatalError("DaemonXPCServer: Failed to encode managed allowlist — this is a bug")
        }
        return data as NSData
    }

    private func encodedUserAllowlist() -> NSData {
        lock.lock()
        let entries = userAllowlist
        lock.unlock()
        guard let data = try? JSONEncoder().encode(entries) else {
            fatalError("DaemonXPCServer: Failed to encode user allowlist — this is a bug")
        }
        return data as NSData
    }

    private func broadcastMergedAllowlistToFilterClients() {
        let data = mergedAllowlistData()
        lock.lock()
        let clients = Array(filterClients.values)
        lock.unlock()
        NSLog("DaemonXPCServer: Broadcasting merged allowlist to %d filter client(s)", clients.count)
        for conn in clients {
            (conn.remoteObjectProxy as? FilterClientProtocol)?.allowlistUpdated(data)
        }
    }

    private func broadcastUserAllowlistToAllGUIClients() {
        let data = encodedUserAllowlist()
        lock.lock()
        let clients = Array(guiClients.values)
        lock.unlock()
        for conn in clients {
            (conn.remoteObjectProxy as? DaemonClientProtocol)?.userAllowlistUpdated(data)
        }
    }

    // MARK: - Disk I/O

    private func loadUserRulesFromDisk() -> [FAARule] {
        guard let data = try? Data(contentsOf: userPolicyURL) else { return [] }

        if let sigData = try? Data(contentsOf: signatureURL) {
            do {
                try PolicySigner.verify(data, signature: sigData)
            } catch {
                NSLog("DaemonXPCServer: Policy signature verification FAILED (%@) — discarding potentially tampered data", "\(error)")
                return []
            }
        } else {
            // No signature yet: first run after enabling signing, or post-update
            // recovery where the old key was inaccessible and was regenerated.
            // Trust the data this once and sign it so future loads are verified.
            NSLog("DaemonXPCServer: No policy signature found — signing existing data (first run or post-update recovery)")
            if let sig = try? PolicySigner.sign(data) {
                try? sig.write(to: signatureURL, options: .atomic)
                try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: signatureURL.path)
            }
        }

        guard let rules = try? JSONDecoder().decode([FAARule].self, from: data) else {
            NSLog("DaemonXPCServer: Failed to decode user policy from disk — starting with empty policy")
            return []
        }
        NSLog("DaemonXPCServer: Loaded %d user rule(s) from disk", rules.count)
        return rules
    }

    private func saveUserRulesToDisk() {
        // 0o700: only root can read, write, or list this directory.
        // createDirectory is a no-op if the directory already exists with withIntermediateDirectories: true.
        let dirAttrs: [FileAttributeKey: Any] = [.posixPermissions: 0o700]
        do {
            try FileManager.default.createDirectory(at: userPolicyDir, withIntermediateDirectories: true, attributes: dirAttrs)
        } catch {
            fatalError("DaemonXPCServer: Failed to create policy directory: \(error)")
        }
        guard let data = try? JSONEncoder().encode(userRules) else {
            fatalError("DaemonXPCServer: Failed to encode user rules for disk — this is a bug")
        }
        do {
            // .atomic writes to a temp file then renames, preserving the original on failure.
            // After the write, lock both files down to root read/write only (0o600).
            try data.write(to: userPolicyURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: userPolicyURL.path)
            if let sig = try? PolicySigner.sign(data) {
                try sig.write(to: signatureURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: signatureURL.path)
            } else {
                NSLog("DaemonXPCServer: Failed to sign policy data — signature file not updated")
            }
        } catch {
            NSLog("DaemonXPCServer: Failed to write user policy to disk: %@", error.localizedDescription)
        }
    }

    private func loadUserAllowlistFromDisk() -> [AllowlistEntry] {
        guard let data = try? Data(contentsOf: allowlistURL) else { return [] }

        if let sigData = try? Data(contentsOf: allowlistSignatureURL) {
            do {
                try PolicySigner.verify(data, signature: sigData)
            } catch {
                NSLog("DaemonXPCServer: Allowlist signature verification FAILED (%@) — discarding potentially tampered data", "\(error)")
                return []
            }
        } else {
            NSLog("DaemonXPCServer: No allowlist signature found — signing existing data (first run or post-update recovery)")
            if let sig = try? PolicySigner.sign(data) {
                try? sig.write(to: allowlistSignatureURL, options: .atomic)
                try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: allowlistSignatureURL.path)
            }
        }

        guard let entries = try? JSONDecoder().decode([AllowlistEntry].self, from: data) else {
            NSLog("DaemonXPCServer: Failed to decode allowlist from disk — starting with empty user allowlist")
            return []
        }
        NSLog("DaemonXPCServer: Loaded %d user allowlist entry/entries from disk", entries.count)
        return entries
    }

    private func saveUserAllowlistToDisk() {
        let dirAttrs: [FileAttributeKey: Any] = [.posixPermissions: 0o700]
        do {
            try FileManager.default.createDirectory(at: userPolicyDir, withIntermediateDirectories: true, attributes: dirAttrs)
        } catch {
            fatalError("DaemonXPCServer: Failed to create policy directory: \(error)")
        }
        guard let data = try? JSONEncoder().encode(userAllowlist) else {
            fatalError("DaemonXPCServer: Failed to encode user allowlist for disk — this is a bug")
        }
        do {
            try data.write(to: allowlistURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: allowlistURL.path)
            if let sig = try? PolicySigner.sign(data) {
                try sig.write(to: allowlistSignatureURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: allowlistSignatureURL.path)
            } else {
                NSLog("DaemonXPCServer: Failed to sign allowlist data — signature file not updated")
            }
        } catch {
            NSLog("DaemonXPCServer: Failed to write user allowlist to disk: %@", error.localizedDescription)
        }
    }
}

// MARK: - NSXPCListenerDelegate

extension DaemonXPCServer: NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        let exportedInterface = NSXPCInterface(with: DaemonServiceProtocol.self)
        let eventClasses = NSSet(array: [FolderOpenEvent.self, AncestorInfo.self, NSArray.self, NSDate.self, NSString.self, NSUUID.self]) as! Set<AnyHashable>
        exportedInterface.setClasses(
            eventClasses,
            for: #selector(DaemonServiceProtocol.reportEvent(_:)),
            argumentIndex: 0,
            ofReply: false
        )
        exportedInterface.setClasses(
            eventClasses,
            for: #selector(DaemonServiceProtocol.fetchRecentEvents(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        let processInfoClasses = NSSet(array: [NSArray.self, RunningProcessInfo.self]) as! Set<AnyHashable>
        exportedInterface.setClasses(
            processInfoClasses,
            for: #selector(DaemonServiceProtocol.fetchProcessList(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
        newConnection.exportedInterface = exportedInterface
        newConnection.exportedObject = ConnectionHandler(server: self, connection: newConnection)

        newConnection.remoteObjectInterface = NSXPCInterface(with: AnyClientProtocol.self)
        newConnection.remoteObjectInterface?.setClasses(
            eventClasses,
            for: #selector(DaemonClientProtocol.folderOpened(_:)),
            argumentIndex: 0,
            ofReply: false
        )

        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            guard let conn = newConnection else { return }
            self?.removeClient(conn)
        }
        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            guard let conn = newConnection else { return }
            NSLog("DaemonXPCServer: Connection interrupted")
            self?.removeClient(conn)
        }

        guard ConnectionValidator.validate(newConnection) else {
            NSLog("DaemonXPCServer: Rejected connection — validation failed")
            return false
        }

        newConnection.resume()
        NSLog("DaemonXPCServer: Accepted connection (protocol v%@)", XPCConstants.protocolVersion)
        return true
    }
}

// MARK: - ConnectionHandler

private final class ConnectionHandler: NSObject, DaemonServiceProtocol {
    weak var server: DaemonXPCServer?
    weak var connection: NSXPCConnection?

    init(server: DaemonXPCServer, connection: NSXPCConnection) {
        self.server = server
        self.connection = connection
        super.init()
    }

    // MARK: Called by GUI app

    func registerClient(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server else { reply(false); return }
        server.addGUIClient(conn)
        reply(true)
    }

    func unregisterClient(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server else { reply(false); return }
        server.removeClient(conn)
        reply(true)
    }

    func isMonitoringActive(withReply reply: @escaping (Bool) -> Void) {
        reply(server?.currentMonitoringStatus() ?? false)
    }

    func fetchRecentEvents(withReply reply: @escaping ([FolderOpenEvent]) -> Void) {
        reply(server?.getRecentEvents() ?? [])
    }

    func addRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let rule = try? JSONDecoder().decode(FAARule.self, from: ruleData as Data) else {
            reply(false)
            return
        }
        server.applyAddRule(rule)
        reply(true)
    }

    func updateRule(_ ruleData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let rule = try? JSONDecoder().decode(FAARule.self, from: ruleData as Data) else {
            reply(false)
            return
        }
        server.applyUpdateRule(rule)
        reply(true)
    }

    func removeRule(_ ruleID: NSUUID, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        server.applyRemoveRule(ruleID: ruleID as UUID)
        reply(true)
    }

    func addAllowlistEntry(_ entryData: NSData, withReply reply: @escaping (Bool) -> Void) {
        guard let server,
              let entry = try? JSONDecoder().decode(AllowlistEntry.self, from: entryData as Data) else {
            reply(false)
            return
        }
        server.applyAddAllowlistEntry(entry)
        reply(true)
    }

    func removeAllowlistEntry(_ entryID: NSUUID, withReply reply: @escaping (Bool) -> Void) {
        guard let server else { reply(false); return }
        server.applyRemoveAllowlistEntry(entryID: entryID as UUID)
        reply(true)
    }

    func requestResync(withReply reply: @escaping () -> Void) {
        guard let server, let conn = connection else { reply(); return }
        server.requestResyncFromFilterClients(requestingConnection: conn)
        reply()
    }

    func fetchProcessList(withReply reply: @escaping ([RunningProcessInfo]) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            reply(ProcessEnumerator.enumerateAll())
        }
    }

    // MARK: Called by opfilter

    func registerFilterClient(withReply reply: @escaping (Bool) -> Void) {
        guard let conn = connection, let server else { reply(false); return }
        server.addFilterClient(conn)
        reply(true)
    }

    func reportEvent(_ event: FolderOpenEvent) {
        NSLog("DaemonXPCServer: Event from opfilter: %@", event.path)
        server?.broadcastEvent(event)
    }

    func reportMonitoringStatus(_ isActive: Bool) {
        NSLog("DaemonXPCServer: Monitoring status from opfilter: %@", isActive ? "active" : "inactive")
        server?.broadcastMonitoringStatus(isActive)
    }
}
