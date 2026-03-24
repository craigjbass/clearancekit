//
//  AuditLoggerTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("AuditLogger")
struct AuditLoggerTests {

    private let auditLogger = AuditLogger()

    private func makeFileEvent(
        path: String = "/protected/file.txt",
        processPath: String = "/usr/bin/test",
        teamID: String = "TEAM1",
        signingID: String = "com.example.app",
        operation: FileOperation = .open,
        processID: pid_t = 100,
        parentPID: pid_t = 1,
        uid: uid_t = 0,
        gid: gid_t = 0
    ) -> FileAuthEvent {
        FileAuthEvent(
            correlationID: UUID(),
            operation: operation,
            path: path,
            processIdentity: ProcessIdentity(pid: processID, pidVersion: 1),
            processID: processID,
            parentPID: parentPID,
            processPath: processPath,
            teamID: teamID,
            signingID: signingID,
            uid: uid,
            gid: gid,
            ttyPath: nil,
            deadline: 0,
            respond: { _, _ in }
        )
    }

    @Test("entry starts with action=FILE_ACCESS")
    func entryStartsWithActionField() {
        let entry = auditLogger.formatEntry(.noRuleApplies, for: makeFileEvent(), ancestors: [], dwellNanoseconds: 0)
        #expect(entry.hasPrefix("action=FILE_ACCESS|"))
    }

    @Test("allowed decision produces ALLOW tag")
    func allowedDecisionProducesAllowTag() {
        let entry = auditLogger.formatEntry(.noRuleApplies, for: makeFileEvent(), ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|decision=ALLOW|"))
    }

    @Test("denied decision produces DENIED tag")
    func deniedDecisionProducesDeniedTag() {
        let decision = PolicyDecision.denied(
            ruleID: UUID(),
            ruleName: "test-rule",
            ruleSource: .user,
            allowedCriteria: ""
        )
        let entry = auditLogger.formatEntry(decision, for: makeFileEvent(), ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|decision=DENIED|"))
    }

    @Test("entry includes path and process path fields")
    func entryIncludesPathFields() {
        let event = makeFileEvent(path: "/some/path/file.db", processPath: "/usr/bin/myapp")
        let entry = auditLogger.formatEntry(.noRuleApplies, for: event, ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|path=/some/path/file.db|"))
        #expect(entry.contains("|processpath=/usr/bin/myapp|"))
        #expect(entry.contains("|process=myapp|"))
    }

    @Test("entry includes access_type from operation")
    func entryIncludesAccessType() {
        let entry = auditLogger.formatEntry(.noRuleApplies, for: makeFileEvent(operation: .open), ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|access_type=open|"))
    }

    @Test("entry includes pid and ppid fields")
    func entryIncludesPidFields() {
        let event = makeFileEvent(processID: 42, parentPID: 7)
        let entry = auditLogger.formatEntry(.noRuleApplies, for: event, ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|pid=42|"))
        #expect(entry.contains("|ppid=7|"))
    }

    @Test("entry includes dwell_ns field")
    func entryIncludesDwellNanoseconds() {
        let entry = auditLogger.formatEntry(.noRuleApplies, for: makeFileEvent(), ancestors: [], dwellNanoseconds: 42000)
        #expect(entry.contains("|dwell_ns=42000"))
    }

    @Test("entry includes operation_id as a valid UUID")
    func entryIncludesValidOperationID() {
        let fixedID = UUID(uuidString: "12345678-1234-1234-1234-123456789ABC")!
        let entry = auditLogger.formatEntry(.noRuleApplies, for: makeFileEvent(), ancestors: [], dwellNanoseconds: 0, operationID: fixedID)
        #expect(entry.contains("|operation_id=12345678-1234-1234-1234-123456789ABC|"))
    }

    @Test("empty ancestors produce empty ancestry tree marker")
    func emptyAncestorsProduceEmptyTreeMarker() {
        let entry = auditLogger.formatEntry(.noRuleApplies, for: makeFileEvent(), ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|ancestry_tree=()|"))
    }

    @Test("multiple ancestors are formatted as a chain in input order")
    func multipleAncestorsFormattedAsChainInOrder() {
        let ancestors = [
            AncestorInfo(path: "/usr/bin/shell", teamID: "ATEAM", signingID: "com.shell"),
            AncestorInfo(path: "/usr/bin/parent", teamID: "BTEAM", signingID: "com.parent"),
        ]
        let entry = auditLogger.formatEntry(.noRuleApplies, for: makeFileEvent(), ancestors: ancestors, dwellNanoseconds: 0)
        let firstRange = entry.range(of: "ATEAM:com.shell")
        let secondRange = entry.range(of: "BTEAM:com.parent")
        #expect(firstRange != nil)
        #expect(secondRange != nil)
        #expect(firstRange!.lowerBound < secondRange!.lowerBound)
        #expect(entry.contains(")->("))
    }

    @Test("builtin policy source produces git hash as policy version")
    func builtinPolicySourceProducesGitHash() {
        let decision = PolicyDecision.allowed(
            ruleID: UUID(),
            ruleName: "builtin-rule",
            ruleSource: .builtin,
            matchedCriterion: "process-path"
        )
        let entry = auditLogger.formatEntry(decision, for: makeFileEvent(), ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|policy_version=\(BuildInfo.gitHash)|"))
    }

    @Test("user policy source produces 'user' as policy version")
    func userPolicySourceProducesUserVersion() {
        let decision = PolicyDecision.allowed(
            ruleID: UUID(),
            ruleName: "user-rule",
            ruleSource: .user,
            matchedCriterion: "process-path"
        )
        let entry = auditLogger.formatEntry(decision, for: makeFileEvent(), ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|policy_version=user|"))
    }

    @Test("mdm policy source produces 'mdm' as policy version")
    func mdmPolicySourceProducesMdmVersion() {
        let decision = PolicyDecision.allowed(
            ruleID: UUID(),
            ruleName: "mdm-rule",
            ruleSource: .mdm,
            matchedCriterion: "process-path"
        )
        let entry = auditLogger.formatEntry(decision, for: makeFileEvent(), ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|policy_version=mdm|"))
    }

    @Test("globally allowed decision produces empty policy version")
    func globallyAllowedProducesEmptyPolicyVersion() {
        let entry = auditLogger.formatEntry(.globallyAllowed, for: makeFileEvent(), ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|policy_version=|"))
    }

    @Test("entry includes team and signing ID fields")
    func entryIncludesSignatureFields() {
        let event = makeFileEvent(teamID: "MYTEAM", signingID: "com.example.myapp")
        let entry = auditLogger.formatEntry(.noRuleApplies, for: event, ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|team_id=MYTEAM|"))
        #expect(entry.contains("|codesigning_id=com.example.myapp|"))
    }

    @Test("invalid signature sentinel is used when both team and signing IDs are empty")
    func invalidSignatureSentinelWhenBothIDsEmpty() {
        let event = makeFileEvent(teamID: "", signingID: "")
        let entry = auditLogger.formatEntry(.noRuleApplies, for: event, ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|team_id=\(invalidSignature)|"))
        #expect(entry.contains("|codesigning_id=\(invalidSignature)|"))
    }

    @Test("apple team ID sentinel is used when only signing ID is set")
    func appleTeamIDSentinelWhenTeamIDEmpty() {
        let event = makeFileEvent(teamID: "", signingID: "com.apple.example")
        let entry = auditLogger.formatEntry(.noRuleApplies, for: event, ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|team_id=\(appleTeamID)|"))
        #expect(entry.contains("|codesigning_id=com.apple.example|"))
    }

    @Test("entry includes policy_name field from decision")
    func entryIncludesPolicyName() {
        let decision = PolicyDecision.denied(
            ruleID: UUID(),
            ruleName: "my-policy-rule",
            ruleSource: .user,
            allowedCriteria: ""
        )
        let entry = auditLogger.formatEntry(decision, for: makeFileEvent(), ancestors: [], dwellNanoseconds: 0)
        #expect(entry.contains("|policy_name=my-policy-rule|"))
    }
}
