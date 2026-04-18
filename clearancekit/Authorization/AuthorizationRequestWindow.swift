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
        let teamID: String
        let path: String
        let isWrite: Bool
        let remainingSeconds: Double
        let ancestors: [AncestorInfo]
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

        let width: CGFloat = 360
        let baseHeight: CGFloat = 120
        let ancestorHeight: CGFloat = 18
        let height = baseHeight + ancestorHeight * CGFloat(request.ancestors.count)

        let screen = NSScreen.main ?? NSScreen.screens[0]
        let origin = NSPoint(
            x: screen.visibleFrame.maxX - width - 8,
            y: screen.visibleFrame.maxY - height - 8
        )

        let newPanel = NSPanel(
            contentRect: NSRect(origin: origin, size: NSSize(width: width, height: height)),
            styleMask: [.nonactivatingPanel, .borderless, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        newPanel.level = .statusBar
        newPanel.isReleasedWhenClosed = false
        newPanel.backgroundColor = .clear
        newPanel.isOpaque = false
        newPanel.hasShadow = true
        newPanel.hidesOnDeactivate = false

        let effect = NSVisualEffectView()
        effect.material = .hudWindow
        effect.blendingMode = .behindWindow
        effect.state = .active
        effect.wantsLayer = true
        effect.layer?.cornerRadius = 12
        effect.layer?.masksToBounds = true

        // Outer horizontal stack: [icon | content]
        let outer = NSStackView()
        outer.orientation = .horizontal
        outer.alignment = .top
        outer.spacing = 12
        outer.edgeInsets = NSEdgeInsets(top: 14, left: 14, bottom: 14, right: 16)
        outer.translatesAutoresizingMaskIntoConstraints = false

        // Biometric icon
        let iconView = NSImageView()
        let iconConfig = NSImage.SymbolConfiguration(pointSize: 28, weight: .regular)
            .applying(NSImage.SymbolConfiguration(hierarchicalColor: .systemRed))
        iconView.image = NSImage(systemSymbolName: "touchid", accessibilityDescription: nil)?
            .withSymbolConfiguration(iconConfig)
        iconView.setContentHuggingPriority(.required, for: .horizontal)
        iconView.setContentCompressionResistancePriority(.required, for: .horizontal)
        outer.addArrangedSubview(iconView)

        // Content stack
        let content = NSStackView()
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 3

        let accessKind = request.isWrite ? "Write" : "Read"
        let headline = NSTextField(labelWithString: "\(accessKind) access requested")
        headline.font = NSFont.systemFont(ofSize: 13, weight: .semibold)
        headline.textColor = .systemRed
        content.addArrangedSubview(headline)

        let pathLine = NSTextField(labelWithString: request.path)
        pathLine.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        pathLine.textColor = .secondaryLabelColor
        pathLine.lineBreakMode = .byTruncatingMiddle
        content.addArrangedSubview(pathLine)

        let shortName = URL(fileURLWithPath: request.processName).lastPathComponent
        let processLine = NSTextField(labelWithString: "\(shortName)  ·  \(request.signingID)  ·  \(request.teamID)")
        processLine.font = NSFont.systemFont(ofSize: 11)
        processLine.textColor = .secondaryLabelColor
        processLine.lineBreakMode = .byTruncatingMiddle
        content.addArrangedSubview(processLine)

        for ancestor in request.ancestors {
            let ancestorShortName = URL(fileURLWithPath: ancestor.path).lastPathComponent
            let line = NSTextField(labelWithString: "↑ \(ancestorShortName)  (\(ancestor.signingID))")
            line.font = NSFont.systemFont(ofSize: 11)
            line.textColor = .tertiaryLabelColor
            line.lineBreakMode = .byTruncatingMiddle
            content.addArrangedSubview(line)
        }

        let countdown = NSTextField(labelWithString: "")
        countdown.font = NSFont.systemFont(ofSize: 11)
        countdown.textColor = .tertiaryLabelColor
        content.addArrangedSubview(countdown)
        self.countdownLabel = countdown

        outer.addArrangedSubview(content)

        effect.addSubview(outer)
        NSLayoutConstraint.activate([
            outer.topAnchor.constraint(equalTo: effect.topAnchor),
            outer.leadingAnchor.constraint(equalTo: effect.leadingAnchor),
            outer.trailingAnchor.constraint(equalTo: effect.trailingAnchor),
            outer.bottomAnchor.constraint(equalTo: effect.bottomAnchor),
        ])

        newPanel.contentView = effect
        newPanel.orderFront(nil)
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
