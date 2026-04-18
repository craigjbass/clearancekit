---
id: ADR-F10
domain: features
date: 2026-03-29
status: Accepted
---
# ADR-F10: MCP Server for App Protections Research

## Context

Building app protection presets for macOS apps required manually inspecting running processes, matching signing IDs to apps via Activity Monitor and Console, and crafting rules — a slow, error-prone workflow repeated for each new preset. Connecting an AI assistant directly to the running policy engine would allow it to observe deny events in real time, look up process signing identities, and draft rules interactively.

## Options

1. Manual process inspection via Activity Monitor and Console — slow, no automation, requires repeated context-switching.
2. Custom CLI tool exposing policy data via stdout — one-way, no interactive rule creation, requires separate shell session.
3. Embedded MCP server in the clearancekit GUI app exposing policy and event data to AI assistants via the Model Context Protocol, with a tamper-resistant opt-in feature flag.

## Decision

An MCP (Model Context Protocol) server is embedded in the clearancekit GUI app (`clearancekit/MCP/`). It exposes the following tools to connected MCP clients:

- `list_events` — real-time deny events with optional path wildcard filtering
- `list_rules`, `add_rule`, `update_rule`, `remove_rule` — policy CRUD (mutations still require Touch ID via `PolicyStore`)
- `list_presets` — current built-in preset definitions

The server is disabled by default and controlled by a signed feature flag stored in the SQLite database (`FeatureFlag` in `Shared/`). The signature uses EC-P256; verification failure defaults to disabled (fail-safe). The GUI exposes a toggle with a security warning recommending users disable the server after use.

The server communicates over a Unix domain socket (`MCPServer.socketPath`). A `.mcp.json` at the project root points Claude Code at the socket path. Multiple correctness issues in the initial socket implementation were fixed (`b406f51`): a `writeAll()` loop handles `EINTR` retry and `EPIPE`/error close; `sun_path` length is validated before `bind()`; `start()` is guarded against double-invocation; `stop()` closes the server fd, shuts down active connections, and resets `serverFd`; `EINTR`/`EAGAIN` are distinguished from real read errors and EOF; malformed frames return JSON-RPC `-32700 Parse error` instead of being silently dropped.

`enforce_on_write_only` is exposed via `add_rule` and `update_rule` (`c6cff32`). `list_rules` and `list_presets` render a `[writes only]` tag for rules where the flag is set.

Active MCP agent sessions are shown in an "MCP Agents" sidebar view where sessions can be individually revoked.

## Consequences

- The MCP server is an opt-in development and research tool, not a production feature. It is disabled by default.
- The feature flag requires explicit creation and signing; an unsigned or absent flag is treated as disabled.
- The server exposes real-time deny events and rule management to any connected MCP client, including AI assistants. Users are warned to disable it after use.
- Used during ClearanceKit development to discover process signing IDs for preset creation, significantly accelerating the preset authoring workflow.
- The server is embedded in the GUI app, not in opfilter, so it operates with GUI-level privilege and routes all mutations through the existing Touch ID-gated `PolicyStore` flow.
