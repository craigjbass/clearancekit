//
//  AuthorizationRequestWindow.swift
//  clearancekit
//

import AppKit
import LocalAuthentication

@MainActor
final class AuthorizationRequestWindow: NSObject {
    static let shared = AuthorizationRequestWindow()

    struct AuthRequest {
        let processName: String
        let signingID: String
        let path: String
        let isWrite: Bool
        let remainingSeconds: Double
        let reply: (Bool) -> Void
    }

    private var panel: NSPanel?
    private var pendingRequests: [AuthRequest] = []
    private var countdownTimer: Timer?
    private var currentDeadline: Date?
    private var countdownLabel: NSTextField?

    func enqueue(_ request: AuthRequest) {
        pendingRequests.append(request)
        if panel == nil {
            showNext()
        }
    }

    private func showNext() {
        guard let request = pendingRequests.first else { return }
        currentDeadline = Date().addingTimeInterval(request.remainingSeconds)

        let newPanel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 420, height: 200),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        newPanel.level = .floating
        newPanel.title = "ClearanceKit Authorization"
        newPanel.isReleasedWhenClosed = false
        newPanel.center()

        let container = NSStackView()
        container.orientation = .vertical
        container.alignment = .leading
        container.spacing = 12
        container.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        container.translatesAutoresizingMaskIntoConstraints = false

        let headline = NSTextField(labelWithString: "\(request.isWrite ? "Write" : "Read") access to \(request.path)")
        headline.font = NSFont.systemFont(ofSize: 14, weight: .semibold)
        headline.lineBreakMode = .byTruncatingMiddle
        container.addArrangedSubview(headline)

        let subline = NSTextField(labelWithString: "Requested by \(request.processName)")
        subline.textColor = .secondaryLabelColor
        container.addArrangedSubview(subline)

        let signatureLine = NSTextField(labelWithString: "Signing ID: \(request.signingID)")
        signatureLine.textColor = .secondaryLabelColor
        signatureLine.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        container.addArrangedSubview(signatureLine)

        let countdown = NSTextField(labelWithString: "")
        countdown.textColor = .tertiaryLabelColor
        container.addArrangedSubview(countdown)
        self.countdownLabel = countdown

        newPanel.contentView = container
        newPanel.makeKeyAndOrderFront(nil)
        self.panel = newPanel

        startCountdown()
        runBiometrics(for: request)
    }

    private func startCountdown() {
        countdownTimer?.invalidate()
        countdownTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.updateCountdown()
            }
        }
    }

    private func updateCountdown() {
        guard let deadline = currentDeadline else { return }
        let remaining = deadline.timeIntervalSinceNow
        if remaining <= 0 {
            countdownLabel?.stringValue = "Timed out"
            finish(allowed: false)
            return
        }
        countdownLabel?.stringValue = String(format: "%.1fs remaining", remaining)
    }

    private func runBiometrics(for request: AuthRequest) {
        let context = LAContext()
        let reason = "Authorize \(request.isWrite ? "write" : "read") access to \(request.path)"
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { [weak self] success, _ in
            Task { @MainActor in
                self?.finish(allowed: success)
            }
        }
    }

    private func finish(allowed: Bool) {
        guard let request = pendingRequests.first else { return }
        pendingRequests.removeFirst()
        countdownTimer?.invalidate()
        countdownTimer = nil
        panel?.orderOut(nil)
        panel = nil
        currentDeadline = nil
        countdownLabel = nil
        request.reply(allowed)
        if !pendingRequests.isEmpty {
            showNext()
        }
    }
}
