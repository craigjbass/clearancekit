//
//  clearancekitApp.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import SwiftUI
import AppKit


final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Stay as accessory (no dock icon) but switch to regular when needed
        // so ServiceManagement and SystemExtensions APIs work correctly.
        NSApp.setActivationPolicy(.accessory)
    }
}

@main
struct clearancekitApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @AppStorage("showMenuBarExtra") private var showMenuBarExtra = true

    var body: some Scene {
        MenuBarExtra(
            "App Menu Bar Extra",
            systemImage: "star",
            isInserted: $showMenuBarExtra
        ) {
            ContentView()
        }

        Window("Events", id: "events") {
            EventsWindowView()
        }
    }
}
