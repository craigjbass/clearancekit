//
//  EventListFilterTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("EventListFilter")
struct EventListFilterTests {

    private func makeEvent(
        allowed: Bool,
        policy: NotificationPolicy = .notify,
        matchedRuleID: UUID? = UUID(),
        jailedRuleID: UUID? = nil
    ) -> FolderOpenEvent {
        FolderOpenEvent(
            path: "/test",
            timestamp: Date(),
            processID: 1,
            processPath: "/usr/bin/test",
            accessAllowed: allowed,
            matchedRuleID: matchedRuleID,
            jailedRuleID: jailedRuleID,
            notificationPolicy: policy
        )
    }

    private func makeFilter(
        decision: EventFilter = .all,
        defaultAllows: DefaultAllowVisibility = .shown,
        quietList: QuietListVisibility = .hidden
    ) -> EventListFilter {
        EventListFilter(decision: decision, defaultAllows: defaultAllows, quietList: quietList)
    }

    // MARK: - Quiet list visibility

    @Test("quiet denies are hidden when quiet list visibility is hidden")
    func quietDeniesHiddenByDefault() {
        let quietDeny = makeEvent(allowed: false, policy: .quiet)

        let visible = makeFilter(quietList: .hidden).apply(to: [quietDeny])

        #expect(visible.isEmpty)
    }

    @Test("quiet denies are shown when quiet list visibility is shown")
    func quietDeniesShownWhenRequested() {
        let quietDeny = makeEvent(allowed: false, policy: .quiet)

        let visible = makeFilter(quietList: .shown).apply(to: [quietDeny])

        #expect(visible.map(\.eventID) == [quietDeny.eventID])
    }

    @Test("non-quiet denies and allows are unaffected by quiet list visibility")
    func otherEventsUnaffectedByQuietListVisibility() {
        let notifyDeny = makeEvent(allowed: false)
        let allow = makeEvent(allowed: true)

        let visible = makeFilter(quietList: .hidden).apply(to: [notifyDeny, allow])

        #expect(visible.map(\.eventID) == [notifyDeny.eventID, allow.eventID])
    }

    // MARK: - Decision filter

    @Test("allow filter keeps only allowed events")
    func allowFilterKeepsAllowedEvents() {
        let deny = makeEvent(allowed: false)
        let allow = makeEvent(allowed: true)

        let visible = makeFilter(decision: .allow).apply(to: [deny, allow])

        #expect(visible.map(\.eventID) == [allow.eventID])
    }

    @Test("deny filter keeps only denied events")
    func denyFilterKeepsDeniedEvents() {
        let deny = makeEvent(allowed: false)
        let allow = makeEvent(allowed: true)

        let visible = makeFilter(decision: .deny).apply(to: [deny, allow])

        #expect(visible.map(\.eventID) == [deny.eventID])
    }

    @Test("all filter keeps allowed and denied events")
    func allFilterKeepsEveryEvent() {
        let deny = makeEvent(allowed: false)
        let allow = makeEvent(allowed: true)

        let visible = makeFilter(decision: .all).apply(to: [deny, allow])

        #expect(visible.count == 2)
    }

    // MARK: - Default allows

    @Test("default allows are hidden when visibility is hidden")
    func defaultAllowsHidden() {
        let defaultAllow = makeEvent(allowed: true, matchedRuleID: nil)

        let visible = makeFilter(defaultAllows: .hidden).apply(to: [defaultAllow])

        #expect(visible.isEmpty)
    }

    @Test("default allows are shown when visibility is shown")
    func defaultAllowsShown() {
        let defaultAllow = makeEvent(allowed: true, matchedRuleID: nil)

        let visible = makeFilter(defaultAllows: .shown).apply(to: [defaultAllow])

        #expect(visible.count == 1)
    }

    @Test("rule-matched and jailed allows stay visible when default allows are hidden")
    func ruleMatchedAllowsStayVisible() {
        let ruleAllow = makeEvent(allowed: true)
        let jailedAllow = makeEvent(allowed: true, matchedRuleID: nil, jailedRuleID: UUID())

        let visible = makeFilter(defaultAllows: .hidden).apply(to: [ruleAllow, jailedAllow])

        #expect(visible.count == 2)
    }

    @Test("denies without a matched rule stay visible when default allows are hidden")
    func unmatchedDeniesStayVisible() {
        let deny = makeEvent(allowed: false, matchedRuleID: nil)

        let visible = makeFilter(defaultAllows: .hidden).apply(to: [deny])

        #expect(visible.count == 1)
    }

    @Test("filtering preserves event order")
    func filteringPreservesOrder() {
        let first = makeEvent(allowed: false)
        let second = makeEvent(allowed: false)
        let third = makeEvent(allowed: false)

        let visible = makeFilter().apply(to: [first, second, third])

        #expect(visible.map(\.eventID) == [first.eventID, second.eventID, third.eventID])
    }
}
