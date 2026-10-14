//
//  DoubleStarCompatibilityCopyTests.swift
//  clearancekitTests
//

import Testing

@Suite("DoubleStarCompatibilityCopy")
struct DoubleStarCompatibilityCopyTests {
    @Test("banner title uses the singular for one rule")
    func bannerTitleSingular() {
        #expect(DoubleStarCompatibilityCopy.bannerTitle(ruleCount: 1) == "1 rule uses `**` compatibility mode")
    }

    @Test("banner title uses the plural for more than one rule")
    func bannerTitlePlural() {
        #expect(DoubleStarCompatibilityCopy.bannerTitle(ruleCount: 3) == "3 rules use `**` compatibility mode")
    }
}
