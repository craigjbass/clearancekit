//
//  BundleUpdaterSignatureTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("BundleUpdaterSignature")
struct BundleUpdaterSignatureTests {

    @Test("exact match returns true")
    func exactMatchReturnsTrue() {
        let sig = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle")
        #expect(sig.matches(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle"))
    }

    @Test("wrong teamID returns false")
    func wrongTeamIDReturnsFalse() {
        let sig = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle")
        #expect(!sig.matches(teamID: "OTHER", signingID: "org.sparkle-project.Sparkle"))
    }

    @Test("wrong signingID returns false")
    func wrongSigningIDReturnsFalse() {
        let sig = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "org.sparkle-project.Sparkle")
        #expect(!sig.matches(teamID: "SPARKLE", signingID: "org.sparkle-project.OtherTool"))
    }

    @Test("wildcard signingID matches any signing ID from the same team")
    func wildcardSigningIDMatchesAnySigningID() {
        let sig = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "*")
        #expect(sig.matches(teamID: "SPARKLE", signingID: "org.sparkle-project.Downloader"))
        #expect(sig.matches(teamID: "SPARKLE", signingID: "org.sparkle-project.Installer"))
    }

    @Test("wildcard signingID does not match different team")
    func wildcardSigningIDDoesNotMatchDifferentTeam() {
        let sig = BundleUpdaterSignature(teamID: "SPARKLE", signingID: "*")
        #expect(!sig.matches(teamID: "OTHER", signingID: "org.sparkle-project.Sparkle"))
    }
}
