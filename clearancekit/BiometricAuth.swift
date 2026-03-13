//
//  BiometricAuth.swift
//  clearancekit
//

import LocalAuthentication

enum BiometricAuth {
    static func authenticate(reason: String) async throws {
        let context = LAContext()
        var canError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &canError) else {
            throw canError ?? LAError(.biometryNotAvailable)
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
                if success {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: error ?? LAError(.authenticationFailed))
                }
            }
        }
    }
}
