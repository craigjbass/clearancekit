//
//  OnePassword.swift
//  clearancekit
//

import Foundation

private let onePasswordSignatures: [ProcessSignature] = [
    sig("2BUA8C4S2C", "com.1password.1password"),
    sig("2BUA8C4S2C", "com.1password.1password.helper"),
    sig("2BUA8C4S2C", "com.1password.1password.helper.xpc"),
    sig("2BUA8C4S2C", "com.agilebits.onepassword7"),
    sig("2BUA8C4S2C", "com.agilebits.onepassword7-helper"),
]

// NOTE: Paths verified against 1Password 8; 1Password 7 paths may need adjustment.
let onePassword8Preset = AppPreset(
    id: "1password8-data-protection",
    appName: "1Password",
    appBundlePath: "/Applications/1Password.app",
    description: "Prevents other processes from reading the 1Password vault database. Only 1Password may open files in its data directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "19B1892A-245D-4EB1-A283-B68AA5501049")!,
            protectedPathPrefix: "/Users/*/Library/Group Containers/2BUA8C4S2C.com.agilebits",
            allowedSignatures: onePasswordSignatures
        ),
    ],
    isExperimental: true
)

let onePassword7Preset = AppPreset(
    id: "1password7-data-protection",
    appName: "1Password 7",
    appBundlePath: "/Applications/1Password 7.app",
    description: "Prevents other processes from reading the 1Password 7 vault database. Only 1Password 7 may open files in its data directories.",
    rules: [
        FAARule(
            id: UUID(uuidString: "44D409E4-E140-4659-BA66-CF1F2481B8A8")!,
            protectedPathPrefix: "/Users/*/Library/Application Support/1Password 4",
            allowedSignatures: onePasswordSignatures
        ),
        FAARule(
            id: UUID(uuidString: "C3FF2E82-40D3-4A45-9E5D-A87B7BD4283C")!,
            protectedPathPrefix: "/Users/*/Library/Group Containers/2BUA8C4S2C.com.agilebits.onepassword4-helper",
            allowedSignatures: onePasswordSignatures
        ),
    ],
    isExperimental: true
)
