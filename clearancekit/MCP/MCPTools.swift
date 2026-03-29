//
//  MCPTools.swift
//  clearancekit
//

import Foundation

// MARK: - MCPDispatcher

enum MCPDispatcher {
    /// Returns (MCPResponse, newSessionID).
    /// newSessionID is non-nil only on a successful `initialize` (the session was just created).
    @MainActor
    static func dispatch(
        _ request: MCPRequest,
        sessionID: UUID?,
        closeFn: @escaping @Sendable () -> Void
    ) async -> (MCPResponse, UUID?) {
        switch request.method {
        case "initialize":
            return await handleInitialize(request, closeFn: closeFn)

        case "notifications/initialized":
            // One-way notification — only valid within an authenticated session.
            guard let id = sessionID, MCPSessionStore.shared.isValid(id) else {
                return (unauthorizedResponse(id: request.id), nil)
            }
            return (MCPResponse(result: .null, id: request.id), nil)

        case "tools/list":
            guard let id = sessionID, MCPSessionStore.shared.isValid(id) else {
                return (unauthorizedResponse(id: request.id), nil)
            }
            return (MCPResponse(result: .object(["tools": .array(toolDefinitions)]), id: request.id), nil)

        case "tools/call":
            guard let id = sessionID, MCPSessionStore.shared.isValid(id) else {
                return (unauthorizedResponse(id: request.id), nil)
            }
            guard let name = request.params?["name"]?.stringValue else {
                return (MCPResponse(error: MCPRPCError(code: -32602, message: "Missing tool name"), id: request.id), nil)
            }
            let args = request.params?["arguments"]?.objectValue ?? [:]
            let response = await callTool(name: name, args: args, sessionID: id, requestID: request.id)
            return (response, nil)

        default:
            return (MCPResponse(error: MCPRPCError(code: -32601, message: "Method not found: \(request.method)"), id: request.id), nil)
        }
    }

    // MARK: - Initialize

    @MainActor
    private static func handleInitialize(
        _ request: MCPRequest,
        closeFn: @escaping @Sendable () -> Void
    ) async -> (MCPResponse, UUID?) {
        let clientName    = request.params?["clientInfo"]?["name"]?.stringValue    ?? "Unknown"
        let clientVersion = request.params?["clientInfo"]?["version"]?.stringValue ?? ""

        do {
            let sessionID = try await MCPSessionStore.shared.issueSession(
                clientName: clientName,
                clientVersion: clientVersion,
                closeFn: closeFn
            )
            return (MCPResponse(result: initializeResult, id: request.id), sessionID)
        } catch {
            return (MCPResponse(
                error: MCPRPCError(code: -32600, message: "Authentication failed: \(error.localizedDescription)"),
                id: request.id
            ), nil)
        }
    }

    // MARK: - Tool dispatch

    @MainActor
    private static func callTool(
        name: String,
        args: [String: JSONValue],
        sessionID: UUID,
        requestID: JSONValue?
    ) async -> MCPResponse {
        MCPSessionStore.shared.recordToolCall(sessionID: sessionID, tool: name)
        do {
            let result: JSONValue
            switch name {
            case "list_events":  result = listEvents(args: args)
            case "list_rules":   result = listRules()
            case "add_rule":     result = try await addRule(args: args)
            case "update_rule":  result = try await updateRule(args: args)
            case "remove_rule":  result = try await removeRule(args: args)
            case "list_presets": result = listPresets()
            default:
                return MCPResponse(error: MCPRPCError(code: -32601, message: "Unknown tool: \(name)"), id: requestID)
            }
            return MCPResponse(result: result, id: requestID)
        } catch {
            return MCPResponse(error: MCPRPCError(code: -32603, message: error.localizedDescription), id: requestID)
        }
    }

    // MARK: - list_events

    @MainActor
    private static func listEvents(args: [String: JSONValue]) -> JSONValue {
        let pathPrefix = args["path_prefix"]?.stringValue
        let limit = args["limit"]?.intValue ?? 200

        var events = XPCClient.shared.events
        if let prefix = pathPrefix {
            events = events.filter { matchesPathPattern($0.path, pattern: prefix) }
        }

        if events.isEmpty {
            let note = pathPrefix.map { " matching \"\($0)\"" } ?? ""
            return text("No events found\(note). Total events in buffer: \(XPCClient.shared.events.count)")
        }

        struct ProcessEntry {
            let signingID: String
            let teamID: String
            let processPath: String
            var denied: Int
            var allowed: Int
            let examplePath: String
        }

        var processMap: [String: ProcessEntry] = [:]
        for event in events {
            let key = "\(event.teamID):\(event.signingID)"
            if var entry = processMap[key] {
                if event.accessAllowed { entry.allowed += 1 } else { entry.denied += 1 }
                processMap[key] = entry
            } else {
                processMap[key] = ProcessEntry(
                    signingID: event.signingID,
                    teamID: event.teamID,
                    processPath: event.processPath,
                    denied: event.accessAllowed ? 0 : 1,
                    allowed: event.accessAllowed ? 1 : 0,
                    examplePath: event.path
                )
            }
        }

        var entries = Array(processMap.values).sorted { $0.denied > $1.denied }
        entries = Array(entries.prefix(limit))

        var lines: [String] = ["Unique processes (\(entries.count)) from \(events.count) events:"]
        for entry in entries {
            let status = entry.denied > 0 ? "DENIED" : "allowed"
            lines.append("\n[\(status)] \(entry.teamID):\(entry.signingID)")
            lines.append("  Process: \(entry.processPath)")
            lines.append("  Events: \(entry.denied) denied, \(entry.allowed) allowed")
            if pathPrefix == nil { lines.append("  Example path: \(entry.examplePath)") }
        }
        return text(lines.joined(separator: "\n"))
    }

    // MARK: - list_rules

    @MainActor
    private static func listRules() -> JSONValue {
        let store = PolicyStore.shared
        var lines: [String] = []
        if !store.baselineRules.isEmpty {
            lines.append("=== Baseline Rules (\(store.baselineRules.count)) ===")
            store.baselineRules.forEach { lines.append(formatRule($0)) }
        }
        if !store.managedRules.isEmpty {
            lines.append("\n=== Managed Rules (\(store.managedRules.count)) ===")
            store.managedRules.forEach { lines.append(formatRule($0)) }
        }
        if !store.userRules.isEmpty {
            lines.append("\n=== User Rules (\(store.userRules.count)) ===")
            store.userRules.forEach { lines.append(formatRule($0)) }
        }
        return text(lines.isEmpty ? "No rules found." : lines.joined(separator: "\n"))
    }

    // MARK: - add_rule

    @MainActor
    private static func addRule(args: [String: JSONValue]) async throws -> JSONValue {
        guard let pathPrefix = args["protected_path_prefix"]?.stringValue, !pathPrefix.isEmpty else {
            throw MCPToolError.missingParameter("protected_path_prefix")
        }
        let signatures = try parseSignatures(from: args["allowed_signatures"])
        let id = args["id"]?.stringValue.flatMap { UUID(uuidString: $0) } ?? UUID()
        let rule = FAARule(id: id, protectedPathPrefix: pathPrefix, source: .user, allowedSignatures: signatures)
        try await PolicyStore.shared.add(rule)
        var lines = ["Rule added:", "  ID: \(rule.id.uuidString)", "  Path: \(pathPrefix)"]
        if !signatures.isEmpty { lines.append("  Signatures: \(signatures.map(\.description).joined(separator: ", "))") }
        return text(lines.joined(separator: "\n"))
    }

    // MARK: - update_rule

    @MainActor
    private static func updateRule(args: [String: JSONValue]) async throws -> JSONValue {
        guard let idString = args["id"]?.stringValue, let id = UUID(uuidString: idString) else {
            throw MCPToolError.missingParameter("id (UUID string)")
        }
        let store = PolicyStore.shared
        guard let existing = store.userRules.first(where: { $0.id == id }) else {
            throw MCPToolError.notFound("No user rule with id \(idString)")
        }
        let signatures = try parseSignatures(from: args["allowed_signatures"])
        let updated = FAARule(
            id: existing.id,
            protectedPathPrefix: existing.protectedPathPrefix,
            source: existing.source,
            allowedProcessPaths: existing.allowedProcessPaths,
            allowedSignatures: signatures,
            allowedAncestorProcessPaths: existing.allowedAncestorProcessPaths,
            allowedAncestorSignatures: existing.allowedAncestorSignatures
        )
        try await store.update(updated)
        return text("Rule updated:\n  ID: \(updated.id.uuidString)\n  Path: \(updated.protectedPathPrefix)\n  Signatures: \(signatures.map(\.description).joined(separator: ", "))")
    }

    // MARK: - remove_rule

    @MainActor
    private static func removeRule(args: [String: JSONValue]) async throws -> JSONValue {
        guard let idString = args["id"]?.stringValue, let id = UUID(uuidString: idString) else {
            throw MCPToolError.missingParameter("id (UUID string)")
        }
        let store = PolicyStore.shared
        guard let rule = store.userRules.first(where: { $0.id == id }) else {
            throw MCPToolError.notFound("No user rule with id \(idString)")
        }
        try await store.remove(rule)
        return text("Rule removed: \(idString) (\(rule.protectedPathPrefix))")
    }

    // MARK: - list_presets

    @MainActor
    private static func listPresets() -> JSONValue {
        let userRules = PolicyStore.shared.userRules
        var lines: [String] = ["App Protection Presets:"]
        for preset in builtInPresets {
            let state = preset.enabledState(in: userRules)
            let drifted = preset.hasDrifted(in: userRules)
            let stateLabel: String
            switch state {
            case .enabled:          stateLabel = drifted ? "enabled (drifted)" : "enabled"
            case .partiallyEnabled: stateLabel = "partial"
            case .disabled:         stateLabel = "disabled"
            }
            lines.append("\n[\(stateLabel)] \(preset.appName) — \(preset.id)")
            lines.append("  Installed: \(preset.isInstalled)")
            for rule in preset.rules {
                lines.append("  Rule [\(rule.id.uuidString)]: \(rule.protectedPathPrefix)")
                if !rule.allowedSignatures.isEmpty {
                    lines.append("    Sigs: \(rule.allowedSignatures.map(\.description).joined(separator: ", "))")
                }
            }
        }
        return text(lines.joined(separator: "\n"))
    }

    // MARK: - Helpers

    private static func parseSignatures(from value: JSONValue?) throws -> [ProcessSignature] {
        guard let array = value?.arrayValue else { return [] }
        return try array.map { item in
            guard let s = item.stringValue, let sig = parseSignature(s) else {
                throw MCPToolError.invalidParameter("Invalid signature \"\(item.stringValue ?? "?")\". Expected \"teamID:signingID\".")
            }
            return sig
        }
    }

    private static func parseSignature(_ s: String) -> ProcessSignature? {
        guard let colonIndex = s.firstIndex(of: ":") else { return nil }
        let team = String(s[s.startIndex..<colonIndex])
        let signing = String(s[s.index(after: colonIndex)...])
        guard !signing.isEmpty else { return nil }
        return ProcessSignature(teamID: team.isEmpty ? appleTeamID : team, signingID: signing)
    }

    private static func matchesPathPattern(_ path: String, pattern: String) -> Bool {
        guard pattern.contains("*") else { return path.hasPrefix(pattern) }
        let escaped = NSRegularExpression.escapedPattern(for: pattern)
            .replacingOccurrences(of: "\\*", with: "[^/]+")
        guard let regex = try? NSRegularExpression(pattern: "^\(escaped)(/.*)?$") else {
            return path.hasPrefix(pattern)
        }
        return regex.firstMatch(in: path, range: NSRange(path.startIndex..., in: path)) != nil
    }

    private static func formatRule(_ rule: FAARule) -> String {
        var lines = ["  [\(rule.id.uuidString)] \(rule.protectedPathPrefix)"]
        if !rule.allowedSignatures.isEmpty {
            lines.append("    Signatures: \(rule.allowedSignatures.map(\.description).joined(separator: ", "))")
        }
        return lines.joined(separator: "\n")
    }

    private static func text(_ s: String) -> JSONValue {
        .object(["content": .array([.object(["type": .string("text"), "text": .string(s)])])])
    }

    private static func unauthorizedResponse(id: JSONValue?) -> MCPResponse {
        MCPResponse(error: MCPRPCError(code: -32600, message: "Unauthorized: connection not authenticated. Send initialize first."), id: id)
    }

    private static var initializeResult: JSONValue {
        .object([
            "protocolVersion": .string("2024-11-05"),
            "capabilities": .object(["tools": .object([:])]),
            "serverInfo": .object(["name": .string("clearancekit"), "version": .string("1.0")])
        ])
    }

    // MARK: - Tool definitions

    private static var toolDefinitions: [JSONValue] {[
        toolDef(
            name: "list_events",
            description: "List recent file access events observed by ClearanceKit, grouped by unique process. Denied events appear first — these signing IDs need to be added to the rule. Supports * wildcard in path_prefix (e.g. /Users/*/Library/Mail).",
            params: [
                "path_prefix": (type: "string",  description: "Path prefix filter, supports * wildcard", required: false),
                "limit":       (type: "integer", description: "Max unique processes to return (default 200)", required: false)
            ]
        ),
        toolDef(
            name: "list_rules",
            description: "List all active FAA rules: baseline (built-in), managed (MDM), and user rules.",
            params: [:]
        ),
        toolDef(
            name: "add_rule",
            description: "Add a new user FAA rule. Requires Touch ID. Pass allowed_signatures: [] to create a blank discovery rule — ClearanceKit will deny and log all access, letting you collect signing IDs via list_events.",
            params: [
                "protected_path_prefix": (type: "string", description: "Path to protect (e.g. /Users/*/Library/Mail)", required: true),
                "allowed_signatures":    (type: "array",  description: "Allowed signing IDs as [\"teamID:signingID\"]. Apple binaries: \"apple:com.apple.Foo\".", required: false),
                "id":                    (type: "string", description: "Optional deterministic UUID (from APP_PROTECTIONS_PLAN.md allocation)", required: false)
            ]
        ),
        toolDef(
            name: "update_rule",
            description: "Replace the allowed_signatures list on an existing user rule. Requires Touch ID.",
            params: [
                "id":                 (type: "string", description: "UUID of the user rule to update", required: true),
                "allowed_signatures": (type: "array",  description: "Complete new list of signatures as [\"teamID:signingID\"]", required: true)
            ]
        ),
        toolDef(
            name: "remove_rule",
            description: "Remove a user FAA rule by ID. Requires Touch ID.",
            params: [
                "id": (type: "string", description: "UUID of the user rule to remove", required: true)
            ]
        ),
        toolDef(
            name: "list_presets",
            description: "List all built-in app protection presets with enabled state and per-rule UUIDs.",
            params: [:]
        )
    ]}

    private static func toolDef(
        name: String,
        description: String,
        params: [String: (type: String, description: String, required: Bool)]
    ) -> JSONValue {
        var properties: [String: JSONValue] = [:]
        var required: [JSONValue] = []
        for (paramName, info) in params {
            var prop: [String: JSONValue] = ["type": .string(info.type), "description": .string(info.description)]
            if info.type == "array" { prop["items"] = .object(["type": .string("string")]) }
            properties[paramName] = .object(prop)
            if info.required { required.append(.string(paramName)) }
        }
        var schema: [String: JSONValue] = ["type": .string("object"), "properties": .object(properties)]
        if !required.isEmpty { schema["required"] = .array(required) }
        return .object(["name": .string(name), "description": .string(description), "inputSchema": .object(schema)])
    }
}

// MARK: - MCPToolError

private enum MCPToolError: LocalizedError {
    case missingParameter(String)
    case invalidParameter(String)
    case notFound(String)

    var errorDescription: String? {
        switch self {
        case .missingParameter(let n): return "Missing required parameter: \(n)"
        case .invalidParameter(let m): return "Invalid parameter: \(m)"
        case .notFound(let m):         return m
        }
    }
}
