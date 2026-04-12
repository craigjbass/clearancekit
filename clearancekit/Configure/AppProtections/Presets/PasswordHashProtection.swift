//
//  PasswordHashProtection.swift
//  clearancekit
//

import Foundation

let passwordHashProtectionPreset = AppPreset(
    id: "password-hash-protection",
    appName: "Password Hash Protection",
    description: "Restricts access to the local user password hash store. Only the Directory Services daemon may read or write these files. Prevents tools like dscl from extracting hashed credentials.",
    rules: [
        FAARule(
            id: UUID(uuidString: "D7917924-5B84-472B-B45D-15C3FC2F727D")!,
            protectedPathPrefix: "/var/db/dslocal/nodes/Default/users",
            allowedSignatures: [
                apple("com.apple.opendirectoryd"),
                apple("com.apple.dirhelper"),
            ]
        ),
    ],
    symbolName: "person.badge.key.fill",
    isExperimental: true
)
