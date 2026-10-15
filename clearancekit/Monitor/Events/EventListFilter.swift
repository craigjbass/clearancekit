//
//  EventListFilter.swift
//  clearancekit
//

import Foundation

enum EventFilter: String, CaseIterable {
    case all = "All"
    case allow = "Allow"
    case deny = "Deny"
}

enum DefaultAllowVisibility {
    case hidden
    case shown
}

enum QuietListVisibility {
    case hidden
    case shown
}

struct EventListFilter {
    let decision: EventFilter
    let defaultAllows: DefaultAllowVisibility
    let quietList: QuietListVisibility

    func apply(to events: [FolderOpenEvent]) -> [FolderOpenEvent] {
        events.filter { matchesDecision($0) && passesDefaultAllowVisibility($0) && passesQuietListVisibility($0) }
    }

    private func matchesDecision(_ event: FolderOpenEvent) -> Bool {
        switch decision {
        case .all:   return true
        case .allow: return event.accessAllowed
        case .deny:  return !event.accessAllowed
        }
    }

    private func passesDefaultAllowVisibility(_ event: FolderOpenEvent) -> Bool {
        switch defaultAllows {
        case .shown:  return true
        case .hidden: return !event.isDefaultAllow
        }
    }

    private func passesQuietListVisibility(_ event: FolderOpenEvent) -> Bool {
        switch quietList {
        case .shown:  return true
        case .hidden: return !event.isQuietDeny
        }
    }
}

private extension FolderOpenEvent {
    var isDefaultAllow: Bool {
        accessAllowed && matchedRuleID == nil && jailedRuleID == nil
    }
}
