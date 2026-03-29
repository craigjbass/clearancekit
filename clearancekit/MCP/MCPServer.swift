//
//  MCPServer.swift
//  clearancekit
//
//  MCP transport: Unix domain socket at socketPath.
//  Each connection reads/writes newline-delimited JSON-RPC (MCP stdio framing).
//  Connect with: nc -U /tmp/clearancekit-mcp.sock
//

import Foundation
import Darwin

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

// MARK: - MCPServer

final class MCPServer {
    static let socketPath = "/tmp/clearancekit-mcp.sock"

    private var serverFd: Int32 = -1
    private var acceptSource: DispatchSourceRead?

    func start() {
        serverFd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverFd >= 0 else { return }

        Darwin.unlink(Self.socketPath)

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        Self.socketPath.withCString { cStr in
            withUnsafeMutableBytes(of: &addr.sun_path) { dest in
                _ = strlcpy(dest.baseAddress!.assumingMemoryBound(to: CChar.self), cStr, dest.count)
            }
        }

        let bound = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(serverFd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0 else { Darwin.close(serverFd); return }

        Darwin.chmod(Self.socketPath, 0o600)
        guard Darwin.listen(serverFd, 8) == 0 else { Darwin.close(serverFd); return }

        let source = DispatchSource.makeReadSource(fileDescriptor: serverFd, queue: .global(qos: .utility))
        source.setEventHandler { [weak self] in self?.acceptConnection() }
        source.setCancelHandler { [weak self] in
            if let fd = self?.serverFd, fd >= 0 { Darwin.close(fd) }
        }
        source.resume()
        acceptSource = source
    }

    func stop() {
        acceptSource?.cancel()
        acceptSource = nil
        Darwin.unlink(Self.socketPath)
    }

    private func acceptConnection() {
        let clientFd = Darwin.accept(serverFd, nil, nil)
        guard clientFd >= 0 else { return }
        MCPSocketConnection(fd: clientFd).start()
    }
}

// MARK: - MCPSocketConnection

private final class MCPSocketConnection: @unchecked Sendable {
    private let fd: Int32
    private var sessionID: UUID?

    init(fd: Int32) { self.fd = fd }

    func start() {
        Task.detached(priority: .utility) { [weak self] in
            await self?.run()
        }
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

        // Remote end closed — clean up the session.
        if let id = sessionID {
            await MCPSessionStore.shared.connectionClosed(id)
        }
        Darwin.close(fd)
    }

    private func readStream() -> AsyncStream<Data> {
        let capFd = fd
        return AsyncStream { continuation in
            let source = DispatchSource.makeReadSource(fileDescriptor: capFd, queue: .global(qos: .utility))
            source.setEventHandler {
                var buf = [UInt8](repeating: 0, count: 4096)
                let n = Darwin.read(capFd, &buf, buf.count)
                if n > 0 {
                    continuation.yield(Data(buf[0..<n]))
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
        guard let request = try? JSONDecoder().decode(MCPRequest.self, from: data) else { return }

        let (response, newSessionID) = await MCPDispatcher.dispatch(
            request,
            sessionID: sessionID,
            closeFn: { [weak self] in
                guard let self else { return }
                Darwin.close(self.fd)
            }
        )

        if let ns = newSessionID { sessionID = ns }

        guard let responseData = try? JSONEncoder().encode(response) else { return }
        var line = responseData
        line.append(UInt8(ascii: "\n"))
        line.withUnsafeBytes { ptr in
            _ = Darwin.write(fd, ptr.baseAddress!, ptr.count)
        }
    }
}
