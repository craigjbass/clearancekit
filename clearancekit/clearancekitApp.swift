//
//  clearancekitApp.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import SwiftUI
import AppKit
import UserNotifications

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
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

@main
struct clearancekitApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @Environment(\.openWindow) private var openWindow
    @ObservedObject private var nav = NavigationState.shared
    @StateObject private var xpcClient = XPCClient.shared
    @StateObject private var daemonManager = DaemonManager.shared

    var body: some Scene {
        Window("clearancekit", id: "main") {
            ContentView()
        }
        .onChange(of: nav.highlightedEventID) { _, eventID in
            if eventID != nil {
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }
        }

        let marketing = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        MenuBarExtra {
            Text("ClearanceKit \(marketing) \(BuildInfo.gitHash)")
            Divider()
            Button("Show") {
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }
            Divider()
            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
        } label: {
            Image(systemName: menuBarIconName)
                .foregroundStyle(menuBarIconColor)
        }
    }

    private var menuBarIconName: String {
        switch menuBarStatus {
        case .healthy:      return "checkmark.shield"
        case .outdated:     return "exclamationmark.shield"
        case .disconnected: return "exclamationmark.shield"
        case .notWorking:   return "shield.slash"
        }
    }

    private var menuBarIconColor: Color {
        switch menuBarStatus {
        case .healthy:      return .primary
        case .outdated:     return .orange
        case .disconnected: return .red
        case .notWorking:   return .red
        }
    }

    private enum MenuBarStatus {
        case healthy, outdated, disconnected, notWorking
    }

    private var menuBarStatus: MenuBarStatus {
        guard daemonManager.status == .enabled else { return .notWorking }
        guard xpcClient.isConnected else { return .disconnected }
        guard xpcClient.isMonitoringActive else { return .notWorking }
        let appHash = BuildInfo.gitHash.trimmingCharacters(in: CharacterSet(charactersIn: "+"))
        let outdated = (!xpcClient.daemonVersion.isEmpty && xpcClient.daemonVersion.trimmingCharacters(in: CharacterSet(charactersIn: "+")) != appHash)
                    || (!xpcClient.opfilterVersion.isEmpty && xpcClient.opfilterVersion.trimmingCharacters(in: CharacterSet(charactersIn: "+")) != appHash)
        return outdated ? .outdated : .healthy
    }
}
