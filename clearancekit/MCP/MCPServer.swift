//
//  MCPServer.swift
//  clearancekit
//
//  MCP transport: Unix domain socket at MCPServer.socketPath (inside the app sandbox container).
//  Each connection reads/writes newline-delimited JSON-RPC (MCP stdio framing).
//

import Foundation
import Darwin
import os

// MARK: - JSON-RPC Types

indirect enum JSONValue: Codable, Equatable {
    case null
    case bool(Bool)
    case int(Int)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    subscript(key: String) -> JSONValue? {
        guard case .object(let dict) = self else { return nil }
        return dict[key]
    }

    var stringValue: String? {
        guard case .string(let s) = self else { return nil }
        return s
    }

    var intValue: Int? {
        guard case .int(let i) = self else { return nil }
        return i
    }

    var arrayValue: [JSONValue]? {
        guard case .array(let a) = self else { return nil }
        return a
    }

    var objectValue: [String: JSONValue]? {
        guard case .object(let o) = self else { return nil }
        return o
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null; return }
        if let v = try? c.decode(Bool.self) { self = .bool(v); return }
        if let v = try? c.decode(Int.self) { self = .int(v); return }
        if let v = try? c.decode(Double.self) { self = .double(v); return }
        if let v = try? c.decode(String.self) { self = .string(v); return }
        if let v = try? c.decode([JSONValue].self) { self = .array(v); return }
        self = .object(try c.decode([String: JSONValue].self))
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null:          try c.encodeNil()
        case .bool(let v):   try c.encode(v)
        case .int(let v):    try c.encode(v)
        case .double(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .array(let v):  try c.encode(v)
        case .object(let v): try c.encode(v)
        }
    }
}

struct MCPRequest: Decodable {
    let jsonrpc: String
    let method: String
    let params: JSONValue?
    let id: JSONValue?
}

struct MCPResponse: Encodable {
    let jsonrpc: String = "2.0"
    let result: JSONValue?
    let error: MCPRPCError?
    let id: JSONValue?

    init(result: JSONValue, id: JSONValue?) {
        self.result = result; self.error = nil; self.id = id
    }

    init(error: MCPRPCError, id: JSONValue?) {
        self.result = nil; self.error = error; self.id = id
    }

    private enum CodingKeys: String, CodingKey { case jsonrpc, result, error, id }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(jsonrpc, forKey: .jsonrpc)
        if let result { try c.encode(result, forKey: .result) }
        if let error  { try c.encode(error,  forKey: .error) }
        try c.encodeIfPresent(id, forKey: .id)
    }
}

struct MCPRPCError: Encodable {
    let code: Int
    let message: String
}

private let logger = Logger(subsystem: "uk.craigbass.clearancekit", category: "mcp-server")

// MARK: - MCPServer

final class MCPServer: @unchecked Sendable {
    static let socketPath: String = {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/.clearancekit/mcp.sock"
    }()

    private let queue: DispatchQueue
    private var serverFd: Int32 = -1
    private var acceptSource: DispatchSourceRead?
    private var activeConnections: [Int32: MCPSocketConnection] = [:]

    init(queue: DispatchQueue) {
        self.queue = queue
    }

    func start() {
        guard serverFd < 0 else { return }

        // sun_path has a fixed capacity; fail fast rather than silently truncating.
        let maxPathLen = MemoryLayout<sockaddr_un>.size
            - MemoryLayout<UInt8>.size        // sun_len
            - MemoryLayout<sa_family_t>.size  // sun_family
            - 1                               // null terminator
        guard Self.socketPath.utf8.count <= maxPathLen else {
            logger.error("MCPServer: socket path too long (\(Self.socketPath.utf8.count) bytes, max \(maxPathLen))")
            return
        }

        let dir = (Self.socketPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

        serverFd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverFd >= 0 else {
            logger.error("MCPServer: socket() failed errno=\(errno) \(String(cString: strerror(errno)), privacy: .public)")
            return
        }

        Darwin.unlink(Self.socketPath)

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathLen = Self.socketPath.utf8.count
        addr.sun_len = UInt8(MemoryLayout<UInt8>.size + MemoryLayout<sa_family_t>.size + pathLen + 1)

        let pathBytes = Array(Self.socketPath.utf8) + [0]
        withUnsafeMutableBytes(of: &addr.sun_path) { dest in
            for (i, byte) in pathBytes.enumerated() where i < dest.count {
                dest[i] = byte
            }
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(serverFd, $0, addrLen)
            }
        }
        guard bound == 0 else {
            logger.error("MCPServer: bind() failed errno=\(errno) \(String(cString: strerror(errno)), privacy: .public)")
            Darwin.close(serverFd)
            serverFd = -1
            return
        }

        Darwin.chmod(Self.socketPath, 0o600)

        guard Darwin.listen(serverFd, 8) == 0 else {
            logger.error("MCPServer: listen() failed errno=\(errno) \(String(cString: strerror(errno)), privacy: .public)")
            Darwin.close(serverFd)
            serverFd = -1
            return
        }

        let source = DispatchSource.makeReadSource(fileDescriptor: serverFd, queue: queue)
        source.setEventHandler { [weak self] in self?.acceptConnection() }
        source.setCancelHandler { logger.info("MCPServer: Listener closed") }
        acceptSource = source
        source.activate()
        logger.info("MCPServer: Listening on \(Self.socketPath, privacy: .public)")
    }

    func stop() {
        guard serverFd >= 0 else { return }
        acceptSource?.cancel()
        acceptSource = nil
        Darwin.close(serverFd)
        serverFd = -1
        Darwin.unlink(Self.socketPath)
        for conn in activeConnections.values { conn.closeOnce() }
        activeConnections.removeAll()
    }

    private func acceptConnection() {
        let clientFd = Darwin.accept(serverFd, nil, nil)
        guard clientFd >= 0 else {
            logger.error("MCPServer: accept() failed errno=\(errno) \(String(cString: strerror(errno)), privacy: .public)")
            return
        }
        logger.debug("MCPServer: New connection fd=\(clientFd)")
        let conn = MCPSocketConnection(fd: clientFd, queue: queue) { [weak self] closedFd in
            self?.queue.async { self?.activeConnections.removeValue(forKey: closedFd) }
        }
        activeConnections[clientFd] = conn
        conn.start()
    }
}

// MARK: - MCPSocketConnection

private final class MCPSocketConnection: @unchecked Sendable {
    private let fd: Int32
    private let queue: DispatchQueue
    private var sessionID: UUID?
    private let closeLock = OSAllocatedUnfairLock(initialState: false)
    private let onClosed: @Sendable (Int32) -> Void

    init(fd: Int32, queue: DispatchQueue, onClosed: @escaping @Sendable (Int32) -> Void) {
        self.fd = fd
        self.queue = queue
        self.onClosed = onClosed
    }

    func start() {
        Task.detached(priority: .utility) { [weak self] in
            await self?.run()
        }
    }

    func closeOnce() {
        let alreadyClosed = closeLock.withLock { (state: inout Bool) -> Bool in
            if state { return true }
            state = true
            return false
        }
        guard !alreadyClosed else { return }
        Darwin.close(fd)
        onClosed(fd)
    }

    private func run() async {
        var lineBuffer = Data()

        for await chunk in readStream() {
            lineBuffer.append(chunk)
            while let newlineIdx = lineBuffer.firstIndex(of: UInt8(ascii: "\n")) {
                let lineData = Data(lineBuffer[..<newlineIdx])
                lineBuffer = Data(lineBuffer[lineBuffer.index(after: newlineIdx)...])
                if !lineData.isEmpty {
                    await handleLine(lineData)
                }
            }
        }

        if let id = sessionID {
            await MCPSessionStore.shared.connectionClosed(id)
        }
        closeOnce()
    }

    private func readStream() -> AsyncStream<Data> {
        let capFd = fd
        return AsyncStream { continuation in
            let source = DispatchSource.makeReadSource(fileDescriptor: capFd, queue: queue)
            source.setEventHandler {
                var buf = [UInt8](repeating: 0, count: 4096)
                let n = Darwin.read(capFd, &buf, buf.count)
                if n > 0 {
                    continuation.yield(Data(buf[0..<n]))
                } else if n == 0 {
                    continuation.finish()
                    source.cancel()
                } else if errno == EINTR || errno == EAGAIN {
                    return  // transient — wait for next readiness notification
                } else {
                    continuation.finish()
                    source.cancel()
                }
            }
            source.setCancelHandler { continuation.finish() }
            source.resume()
            continuation.onTermination = { _ in source.cancel() }
        }
    }

    private func handleLine(_ data: Data) async {
        guard let request = try? JSONDecoder().decode(MCPRequest.self, from: data) else {
            logger.warning("MCPSocketConnection: malformed JSON-RPC on fd=\(self.fd)")
            sendParseError()
            return
        }

        let (response, newSessionID) = await MCPDispatcher.dispatch(
            request,
            sessionID: sessionID,
            closeFn: { [weak self] in self?.closeOnce() }
        )

        if let ns = newSessionID { sessionID = ns }

        guard let responseData = try? JSONEncoder().encode(response) else { return }
        var line = responseData
        line.append(UInt8(ascii: "\n"))
        writeAll(line)
    }

    private func sendParseError() {
        let parseError = MCPResponse(error: MCPRPCError(code: -32700, message: "Parse error"), id: nil)
        guard let responseData = try? JSONEncoder().encode(parseError) else { return }
        var line = responseData
        line.append(UInt8(ascii: "\n"))
        writeAll(line)
    }

    private func writeAll(_ data: Data) {
        data.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            var offset = 0
            while offset < ptr.count {
                let n = Darwin.write(fd, base.advanced(by: offset), ptr.count - offset)
                if n > 0 {
                    offset += n
                } else if n < 0 && errno == EINTR {
                    continue
                } else {
                    // EPIPE or other write error — peer closed or broken pipe
                    closeOnce()
                    return
                }
            }
        }
    }
}
