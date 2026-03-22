//
//  CacheDecisionProcessorTests.swift
//  clearancekitTests
//

import Testing

// MARK: - JailFileAccessEventCacheDecisionProcessor

@Suite("JailFileAccessEventCacheDecisionProcessor")
struct JailFileAccessEventCacheDecisionProcessorTests {

    private let processor = JailFileAccessEventCacheDecisionProcessor()

    @Test("returns cache when no jails are configured")
    func noJailsConfiguredReturnsCache() {
        let decision = processor.decide(jailsConfigured: false)
        #expect(decision == .cache)
        #expect(decision.shouldCache)
    }

    @Test("returns noCache when jails are configured")
    func jailsConfiguredReturnsNoCache() {
        let decision = processor.decide(jailsConfigured: true)
        #expect(decision == .noCache)
        #expect(!decision.shouldCache)
    }
}

// MARK: - FileAccessEventCacheDecisionProcessor

@Suite("FileAccessEventCacheDecisionProcessor")
struct FileAccessEventCacheDecisionProcessorTests {

    private let processor = FileAccessEventCacheDecisionProcessor()

    @Test("allow decision caches")
    func allowDecisionCaches() {
        #expect(processor.decide(outcome: .allow, ancestorEvaluationRequired: false))
    }

    @Test("allow decision caches even when ancestor evaluation was required")
    func allowDecisionCachesWithAncestorEvaluation() {
        #expect(processor.decide(outcome: .allow, ancestorEvaluationRequired: true))
    }

    @Test("deny decision without ancestor evaluation caches")
    func denyDecisionWithoutAncestorEvaluationCaches() {
        #expect(processor.decide(outcome: .deny, ancestorEvaluationRequired: false))
    }

    @Test("deny decision with ancestor evaluation does not cache")
    func denyDecisionWithAncestorEvaluationDoesNotCache() {
        #expect(!processor.decide(outcome: .deny, ancestorEvaluationRequired: true))
    }
}
