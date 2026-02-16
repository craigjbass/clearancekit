//
//  clearancekitApp.swift
//  clearancekit
//
//  Created by Craig J. Bass on 26/01/2026.
//

import SwiftUI
import AppKit


@main
struct clearancekitApp: App {
    @AppStorage("showMenuBarExtra") private var showMenuBarExtra = true
        
    var body: some Scene {
        MenuBarExtra(
            "App Menu Bar Extra",
            systemImage: "star",
            isInserted: $showMenuBarExtra
        ) {
            ContentView()
        }
    }
}
