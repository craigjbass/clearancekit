//
//  NSXPCConnection+AuditToken.swift
//  clearancekit-daemon
//
//  NSXPCConnection.auditToken is public API since macOS 14 but is not exposed in
//  Swift's Foundation overlay because audit_token_t requires <bsm/audit.h>.
//  audit_token_t IS available in Swift via `import Security` (SecTaskCreateWithAuditToken).
//
//  On ARM64 (the only architecture supported by macOS 26+) all ObjC methods use
//  objc_msgSend regardless of return size, so calling the getter via its IMP with a
//  @convention(c) function pointer is safe and ABI-correct.
//

import Foundation
import Security
import ObjectiveC.runtime

extension NSXPCConnection {
    var xpcAuditToken: audit_token_t {
        typealias AuditTokenGetter = @convention(c) (AnyObject, Selector) -> audit_token_t
        let sel = NSSelectorFromString("auditToken")
        guard let method = class_getInstanceMethod(object_getClass(self), sel) else {
            preconditionFailure("NSXPCConnection has no auditToken method — this is a macOS 14+ API")
        }
        let imp = method_getImplementation(method)
        return unsafeBitCast(imp, to: AuditTokenGetter.self)(self, sel)
    }
}
