//
//  AWSCredentialProtection.swift
//  clearancekit
//

import Foundation

// NOTE: For stronger protection against AI tool prompt injection attacks, consider
// also adding a JailRule for your AI coding assistant — restricting it to your
// project directory prevents it from accessing credential paths entirely.
let awsCredentialProtectionPreset = AppPreset(
    id: "aws-credential-protection",
    appName: "AWS Credential Protection",
    description: "Prevents unauthorised processes from reading or modifying your AWS credentials. Protects against AI tool prompt injection attacks that attempt to exfiltrate cloud credentials from ~/.aws. Only the AWS CLI and system processes may access these files.",
    rules: [
        FAARule(
            id: UUID(uuidString: "6D58827A-3B16-420A-82E9-47E84427C44A")!,
            protectedPathPrefix: "/Users/*/.aws/credentials",
            allowedProcessPaths: [
                "/usr/local/bin/aws",
                "/opt/homebrew/bin/aws",
            ],
            allowedSignatures: [
                apple("com.apple.installer"),
            ]
        ),
        FAARule(
            id: UUID(uuidString: "395A05E6-8973-455E-B1BA-C320AE1F43DA")!,
            protectedPathPrefix: "/Users/*/.aws/config",
            allowedProcessPaths: [
                "/usr/local/bin/aws",
                "/opt/homebrew/bin/aws",
            ],
            allowedSignatures: [
                apple("com.apple.installer"),
            ],
            enforceOnWriteOnly: true
        ),
    ],
    symbolName: "cloud.fill",
    isExperimental: true
)
