//
//  PresetResponsibleProcessTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("Preset WebKit signatures")
struct PresetResponsibleProcessTests {
    @Test("Safari preset lists no WebKit signature")
    func safariPresetListsNoWebKitSignature() {
        let signingIDs = safariPreset.rules.flatMap(\.allowedSignatures).map(\.signingID)

        #expect(!signingIDs.contains { $0.hasPrefix("com.apple.WebKit.") })
    }
}
