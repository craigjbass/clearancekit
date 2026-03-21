//
//  MutePath.swift
//  opfilter
//

/// Returns the literal path prefix to pass to `es_mute_path` for a given pattern.
/// Stops at the first path component that contains a wildcard character.
func mutePath(for pattern: String) -> String {
    var literal: [String] = []
    for component in pattern.split(separator: "/", omittingEmptySubsequences: false).map(String.init) {
        if component.contains("*") || component.contains("?") { break }
        literal.append(component)
    }
    let result = literal.joined(separator: "/")
    return result.isEmpty ? "/" : result
}
