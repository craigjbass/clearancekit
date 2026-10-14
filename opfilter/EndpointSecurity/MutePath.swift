//
//  MutePath.swift
//  opfilter
//

import EndpointSecurity

/// Returns the literal path prefix to pass to `es_mute_path` for a given pattern.
/// Stops at the first path component that contains a wildcard character.
/// Empty components and a trailing slash are removed, because ES reports
/// paths without them.
func mutePath(for pattern: String) -> String {
    let literalComponents = pattern
        .split(separator: "/", omittingEmptySubsequences: true)
        .prefix { !$0.contains("*") && !$0.contains("?") }
    return "/\(literalComponents.joined(separator: "/"))"
}

enum MuteTargetKind {
    case prefix
    case literal
}

struct MuteTarget: Hashable {
    let path: String
    let kind: MuteTargetKind
}

// A rename or clone of any parent directory moves the protected paths with it,
// so each literal parent must also generate events.
func muteTargets(for pattern: String) -> Set<MuteTarget> {
    let prefix = mutePath(for: pattern)
    let parents = literalParents(of: prefix).map { MuteTarget(path: $0, kind: .literal) }
    return Set([MuteTarget(path: prefix, kind: .prefix)] + parents)
}

func muteTargets(for rules: [FAARule]) -> Set<MuteTarget> {
    rules.reduce(into: Set<MuteTarget>()) { targets, rule in
        targets.formUnion(muteTargets(for: rule.protectedPathPrefix))
    }
}

private func literalParents(of path: String) -> [String] {
    let components = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
    return components.indices.map { index in "/" + components[..<index].joined(separator: "/") }
}

extension MuteTargetKind {
    var esMutePathType: es_mute_path_type_t {
        switch self {
        case .prefix: return ES_MUTE_PATH_TYPE_TARGET_PREFIX
        case .literal: return ES_MUTE_PATH_TYPE_TARGET_LITERAL
        }
    }
}
