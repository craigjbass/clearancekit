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

        MenuBarExtra("clearancekit", systemImage: "checkmark.shield") {
            Button("Show") {
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }
            Divider()
            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
        }
    }
}
