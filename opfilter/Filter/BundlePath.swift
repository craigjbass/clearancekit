//
//  BundlePath.swift
//  opfilter
//

import Foundation

enum BundlePath {
    static let protectedPrefixes: [String] = {
        var prefixes = ["/Applications/"]
        let usersURL = URL(fileURLWithPath: "/Users")
        let userDirs = (try? FileManager.default.contentsOfDirectory(
            at: usersURL,
            includingPropertiesForKeys: nil,
            options: .skipsHiddenFiles
        )) ?? []
        for dir in userDirs {
            prefixes.append(dir.appendingPathComponent("Applications").path + "/")
        }
        return prefixes
    }()

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
