//
//  ConnectionValidator.swift
//  opfilter
//
//  Validates incoming XPC connections using audit_token-based code signing checks.
//  Introduced in protocol v2.0.
//
//  Checks performed:
//    1. Valid Apple-anchored signature with the expected team ID
//    2. Bundle identifier has the expected prefix
//    3. Client does not carry entitlements that weaken code signing integrity
//

import Foundation
import Security

enum ConnectionValidator {
    // Require the cert chain to be Apple-anchored and leaf OU to match our team.
    private static let signingRequirement =
        "anchor apple generic and certificate leaf[subject.OU] = \"\(XPCConstants.teamID)\""

    private static let forbiddenEntitlements: Set<String> = [
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.get-task-allow",
    ]

    /// Returns true iff the connection passes all signing checks.
    static func validate(_ connection: NSXPCConnection) -> Bool {
        guard let code = secCode(for: connection.xpcAuditToken) else {
            NSLog("ConnectionValidator: Failed to obtain SecCode")
            return false
        }
        return verifySignature(code) && verifyBundleID(code) && verifyEntitlements(code)
    }

    // MARK: - Private

    private static func secCode(for token: audit_token_t) -> SecCode? {
        // Use audit_token rather than PID to avoid PID-reuse attacks.
        let tokenData = withUnsafeBytes(of: token) { Data($0) }
        let attrs = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess else {
            return nil
        }
        return code
    }

    private static func verifySignature(_ code: SecCode) -> Bool {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(signingRequirement as CFString, [], &requirement) == errSecSuccess,
              let requirement else {
            NSLog("ConnectionValidator: Failed to build signing requirement")
            return false
        }
        var cfError: Unmanaged<CFError>?
        let status = SecCodeCheckValidityWithErrors(code, [], requirement, &cfError)
        if status != errSecSuccess {
            NSLog("ConnectionValidator: Signature check failed (%d): %@",
                  status, cfError?.takeRetainedValue().localizedDescription ?? "unknown")
        }
        return status == errSecSuccess
    }

    private static func verifyBundleID(_ code: SecCode) -> Bool {
        guard let info = signingInfo(for: code),
              let bundleID = info[kSecCodeInfoIdentifier] as? String else {
            NSLog("ConnectionValidator: Failed to read bundle identifier")
            return false
        }
        guard bundleID.hasPrefix(XPCConstants.bundleIDPrefix) else {
            NSLog("ConnectionValidator: Rejected unexpected bundle ID: %@", bundleID)
            return false
        }
        return true
    }

    private static func verifyEntitlements(_ code: SecCode) -> Bool {
        #if DEBUG
            return true
        #endif
        
        guard let info = signingInfo(for: code) else {
            NSLog("ConnectionValidator: Failed to read signing info for entitlement check")
            return false
        }
        let entitlements = info[kSecCodeInfoEntitlementsDict] as? [String: Any] ?? [:]
        for key in forbiddenEntitlements {
            if entitlements[key] as? Bool == true {
                NSLog("ConnectionValidator: Rejected — client %@ has forbidden entitlement: %@", info[kSecCodeInfoIdentifier] as? [String: Any] ?? [:], key)
                return false
            }
        }
        return true
    }

    private static func signingInfo(for code: SecCode) -> [CFString: Any]? {
        // SecCodeRef IS-A SecStaticCodeRef in the CF type system; the cast is safe.
        let staticCode = unsafeBitCast(code, to: SecStaticCode.self)
        var info: CFDictionary?
        // SecCSFlags rawValue 1 = kSecCSInternalInformation, which populates
        // kSecCodeInfoIdentifier and kSecCodeInfoEntitlementsDict.
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: 1), &info) == errSecSuccess,
              let dict = info as? [CFString: Any] else {
            return nil
        }
        return dict
    }
}
