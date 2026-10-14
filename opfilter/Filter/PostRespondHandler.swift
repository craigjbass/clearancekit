//
//  PostRespondHandler.swift
//  opfilter
//

import Foundation

final class PostRespondHandler: @unchecked Sendable {
    var onEvent: ((FolderOpenEvent) -> Void)?

    private let postRespondQueue: DispatchQueue
    private let quietListProvider: @Sendable () -> [QuietListEntry]
    private let auditLogger = AuditLogger()
    private let ttyNotifier = TTYNotifier()

    init(
        quietListProvider: @escaping @Sendable () -> [QuietListEntry],
        postRespondQueue: DispatchQueue = DispatchQueue(label: "uk.craigbass.clearancekit.post-respond", qos: .background)
    ) {
        self.quietListProvider = quietListProvider
        self.postRespondQueue = postRespondQueue
    }

    func postRespond(fileEvent: FileAuthEvent, decision: PolicyDecision, ancestors: [AncestorInfo], dwellNanoseconds: UInt64) {
        postRespondQueue.async { [self] in
            let allowed = decision.isAllowed

            auditLogger.log(decision, for: fileEvent, ancestors: ancestors, dwellNanoseconds: dwellNanoseconds, operationID: fileEvent.correlationID)

            if !allowed {
                ttyNotifier.writeDenial(path: fileEvent.path, reason: decision.reason, ttyPath: fileEvent.ttyPath)
            }

            let folderOpenEvent = FolderOpenEvent(
                operation: fileEvent.operation.rawValue,
                path: fileEvent.path,
                secondaryPath: fileEvent.secondaryPath,
                timestamp: Date(),
                processID: fileEvent.processID,
                processPath: fileEvent.processPath,
                teamID: fileEvent.teamID,
                signingID: fileEvent.signingID,
                uid: UInt32(fileEvent.uid),
                accessAllowed: allowed,
                decisionReason: decision.reason,
                ancestors: ancestors,
                matchedRuleID: decision.matchedRuleID,
                jailedRuleID: decision.jailedRuleID,
                notificationPolicy: resolveNotificationPolicy(for: fileEvent, decision: decision),
                eventID: fileEvent.correlationID
            )
            onEvent?(folderOpenEvent)
        }
    }

    private func resolveNotificationPolicy(for fileEvent: FileAuthEvent, decision: PolicyDecision) -> NotificationPolicy {
        guard !decision.isAllowed else { return .notify }
        return notificationPolicy(
            processPath: fileEvent.processPath,
            signingID: fileEvent.signingID,
            teamID: fileEvent.teamID,
            quietList: quietListProvider()
        )
    }
}
