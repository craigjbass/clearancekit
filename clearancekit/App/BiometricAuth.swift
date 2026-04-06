//
//  BiometricAuth.swift
//  clearancekit
//

import LocalAuthentication

enum BiometricAuth {
    static func authenticate(reason: String) async throws {
        let context = LAContext()
        var canError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &canError) else {
            throw canError ?? LAError(.passcodeNotSet)
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
                if success {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: error ?? LAError(.authenticationFailed))
                }
            }
        }
    }

    static func isUserCancellation(_ error: Error) -> Bool {
        guard let laError = error as? LAError else { return false }
        return laError.code == .userCancel || laError.code == .systemCancel
    }
}
