//
//  clearancekitApp.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import SwiftUI
import AppKit
import UserNotifications
import Combine

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    private let mcpQueue = DispatchQueue(label: "uk.craigbass.clearancekit.mcp", qos: .utility)
    private lazy var mcpServer = MCPServer(queue: mcpQueue)
    private var mcpEnabledCancellable: AnyCancellable?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }

        XPCClient.shared.shouldResumeAllowEventStream = { NavigationState.shared.isEventsScreenActive }
        XPCClient.shared.shouldResumeMetricsStream = { NavigationState.shared.isMetricsScreenActive }

        mcpEnabledCancellable = XPCClient.shared.$mcpEnabled
            .receive(on: mcpQueue)
            .sink { [weak self] enabled in
                if enabled {
                    self?.mcpServer.start()
                } else {
                    self?.mcpServer.stop()
                }
            }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let userInfo = response.notification.request.content.userInfo
        if let idString = userInfo["eventID"] as? String, let eventID = UUID(uuidString: idString) {
            Task { @MainActor in
                NavigationState.shared.navigate(toEventID: eventID)
            }
        }
        completionHandler()
    }
}

private struct WindowAccessor: NSViewRepresentable {
    let onClose: () -> Void

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            guard let window = view.window else { return }
            window.delegate = context.coordinator
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onClose: onClose)
    }

    final class Coordinator: NSObject, NSWindowDelegate {
        let onClose: () -> Void

        init(onClose: @escaping () -> Void) {
            self.onClose = onClose
        }

        func windowShouldClose(_ sender: NSWindow) -> Bool {
            onClose()
            return false
        }
    }
}

@main
struct clearancekitApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @Environment(\.openWindow) private var openWindow
    @ObservedObject private var nav = NavigationState.shared
    @StateObject private var xpcClient = XPCClient.shared

    var body: some Scene {
        Window("clearancekit", id: "main") {
            ContentView()
                .background(WindowAccessor(onClose: {
                    hideWindow()
                }))
        }
        .onChange(of: nav.highlightedEventID) { _, eventID in
            if eventID != nil {
                showWindow()
            }
        }
        .onChange(of: xpcClient.pendingSignatureIssue) { _, issue in
            if issue != nil {
                showWindow()
            }
        }

        let marketing = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        MenuBarExtra {
            Text("ClearanceKit \(marketing) \(BuildInfo.gitHash)")
            Divider()
            Button("Show") {
                showWindow()
            }
            Button("Check for updates") {
                let cleanHash = BuildInfo.gitHash.trimmingCharacters(in: CharacterSet(charactersIn: "+"))
                var components = URLComponents(string: "https://craigjbass.github.io/clearancekit/update.html")
                components?.queryItems = [URLQueryItem(name: "sha", value: cleanHash)]
                if let url = components?.url { NSWorkspace.shared.open(url) }
            }
            Divider()
            Button("Quit GUI") {
                NSApplication.shared.terminate(nil)
            }
        } label: {
            Image(systemName: menuBarIconName)
                .foregroundStyle(menuBarIconColor)
        }
    }

    private func showWindow() {
        NSApp.setActivationPolicy(.regular)
        openWindow(id: "main")
        NSApp.activate()
        NavigationState.shared.windowVisible = true
    }

    private func hideWindow() {
        NavigationState.shared.windowVisible = false
        XPCClient.shared.endAllowEventStream()
        NSApp.keyWindow?.orderOut(nil)
        DispatchQueue.main.async {
            NSApp.setActivationPolicy(.accessory)
        }
    }

    private var menuBarIconName: String {
        switch menuBarStatus {
        case .healthy:      return "checkmark.shield"
        case .outdated:     return "exclamationmark.shield"
        case .disconnected: return "shield.slash"
        }
    }

    private var menuBarIconColor: Color {
        switch menuBarStatus {
        case .healthy:      return .primary
        case .outdated:     return .orange
        case .disconnected: return .red
        }
    }

    private enum MenuBarStatus {
        case healthy, outdated, disconnected
    }

    private var menuBarStatus: MenuBarStatus {
        guard xpcClient.isConnected else { return .disconnected }
        let appHash = BuildInfo.gitHash.trimmingCharacters(in: CharacterSet(charactersIn: "+"))
        let outdated = !xpcClient.serviceVersion.isEmpty
            && xpcClient.serviceVersion.trimmingCharacters(in: CharacterSet(charactersIn: "+")) != appHash
        return outdated ? .outdated : .healthy
    }
}
