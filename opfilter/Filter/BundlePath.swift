//
//  BundlePath.swift
//  opfilter
//

import Foundation

enum BundlePath {
    static let protectedPrefixes: [String] = [
        "/Applications/",
        NSHomeDirectory() + "/Applications/"
    ]

    static func extract(from accessPath: String) -> String? {
        for prefix in protectedPrefixes {
            guard accessPath.hasPrefix(prefix) else { continue }
            let remainder = String(accessPath.dropFirst(prefix.count))
            for component in remainder.split(separator: "/", omittingEmptySubsequences: true) {
                if component.hasSuffix(".app") {
                    return prefix + component
                }
                break
            }
        }
        return nil
    }
}
