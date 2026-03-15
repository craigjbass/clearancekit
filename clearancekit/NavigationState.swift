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

    private init() {}

    func navigate(toEventID eventID: UUID) {
        selection = .events
        highlightedEventID = eventID
    }
}
