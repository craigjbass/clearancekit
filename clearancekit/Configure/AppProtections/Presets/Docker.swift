//
//  Docker.swift
//  clearancekit
//

import Foundation

let dockerPreset = AppPreset(
    id: "docker-data-protection",
    appName: "Docker",
    appBundlePath: "/Applications/Docker.app",
    description: "Prevents other processes from reading Docker's configuration and credentials. Only Docker processes may open files in its data directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "63555107-DFE5-4A2F-8CA9-8115D3B8DF64")!,
            protectedPathPrefix: "/Users/*/Library/Group Containers/group.com.docker",
            allowedSignatures: [sig("9BNSXJN65R", "*")]
        ),
        FAARule(
            id: UUID(uuidString: "9D7FB36C-2F6A-4612-B9C0-6AA92E7F3215")!,
            protectedPathPrefix: "/Users/*/.docker",
            allowedSignatures: [sig("9BNSXJN65R", "*")]
        ),
    ],
    isExperimental: true
)
