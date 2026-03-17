//
//  ProtectionDraft.swift
//  clearancekit
//

import Foundation

struct ProtectionDraft {
    var appInfo: AppBundleInfo
    var entries: [PathEntry]

    struct PathEntry: Identifiable {
        let id: UUID
        var prefix: String
        var signatures: [ProcessSignature]

        init(prefix: String, signatures: [ProcessSignature]) {
            self.id = UUID()
            self.prefix = prefix
            self.signatures = signatures
        }
    }

    static func from(rules: [FAARule], appInfo: AppBundleInfo) -> ProtectionDraft {
        let entries = rules.map { PathEntry(prefix: $0.protectedPathPrefix, signatures: $0.allowedSignatures) }
        return ProtectionDraft(appInfo: appInfo, entries: entries)
    }

    func toRules() -> [FAARule] {
        entries.map { FAARule(protectedPathPrefix: $0.prefix, allowedSignatures: $0.signatures) }
    }
}
