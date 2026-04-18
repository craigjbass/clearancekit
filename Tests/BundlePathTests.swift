//
//  BundlePathTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("BundlePath")
struct BundlePathTests {
    @Test("/Applications subpath returns bundle root")
    func applicationsSubpath() {
        #expect(
            BundlePath.extract(from: "/Applications/Foo.app/Contents/MacOS/Foo")
            == "/Applications/Foo.app"
        )
    }

    @Test("~/Applications subpath returns expanded home bundle root")
    func homeApplicationsSubpath() {
        let home = NSHomeDirectory()
        #expect(
            BundlePath.extract(from: home + "/Applications/Bar.app/Contents/Resources/icon.png")
            == home + "/Applications/Bar.app"
        )
    }

    @Test("/usr/bin path returns nil")
    func nonBundlePath() {
        #expect(BundlePath.extract(from: "/usr/bin/git") == nil)
    }

    @Test("path that is the bundle root returns itself")
    func bundleRootPath() {
        #expect(
            BundlePath.extract(from: "/Applications/Foo.app")
            == "/Applications/Foo.app"
        )
    }

    @Test("nested .app returns outer .app")
    func nestedApp() {
        #expect(
            BundlePath.extract(from: "/Applications/Foo.app/Contents/PlugIns/Bar.app/Contents/MacOS/Bar")
            == "/Applications/Foo.app"
        )
    }

    @Test("path with no .app component returns nil")
    func noAppComponent() {
        #expect(BundlePath.extract(from: "/Applications/SomeFile.txt") == nil)
    }
}
