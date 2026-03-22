//
//  CacheDecisionProcessor.swift
//  Shared
//

// MARK: - Jail cache decision

public enum JailCacheDecision {
    case cache
    case noCache

    public var shouldCache: Bool {
        switch self {
        case .cache: true
        case .noCache: false
        }
    }
}

public struct JailFileAccessEventCacheDecisionProcessor {
    public init() {}

    public func decide(jailsConfigured: Bool) -> JailCacheDecision {
        jailsConfigured ? .noCache : .cache
    }
}

// MARK: - FAA cache decision

public enum FAADecisionOutcome {
    case allow
    case deny
}

public struct FileAccessEventCacheDecisionProcessor {
    public init() {}

    public func decide(outcome: FAADecisionOutcome, ancestorEvaluationRequired: Bool) -> Bool {
        switch outcome {
        case .allow:
            true
        case .deny:
            !ancestorEvaluationRequired
        }
    }
}
