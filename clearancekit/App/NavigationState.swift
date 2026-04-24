//
//  NavigationState.swift
//  clearancekit
//

import Foundation
import Combine

@MainActor
final class NavigationState: ObservableObject {
    static let shared = NavigationState()

    @Published var selection: SidebarItem = .events
    @Published var highlightedEventID: UUID? = nil
    @Published var windowVisible = false

    private init() {}

    func navigate(toEventID eventID: UUID) {
        selection = .events
        highlightedEventID = eventID
    }

    var isEventsScreenActive: Bool {
        windowVisible && selection == .events
    }
}
