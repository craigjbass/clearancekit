//
//  AccessKindClassifierTests.swift
//  clearancekitTests
//

import Testing
import Foundation

@Suite("AccessKind classification")
struct AccessKindClassifierTests {

    @Test("FREAD only is a read")
    func freadIsRead() {
        #expect(accessKind(forOpenFlags: FREAD) == .read)
    }

    @Test("FWRITE alone is a write")
    func fwriteIsWrite() {
        #expect(accessKind(forOpenFlags: FWRITE) == .write)
    }

    @Test("FREAD | FWRITE is a write")
    func freadFwriteIsWrite() {
        #expect(accessKind(forOpenFlags: FREAD | FWRITE) == .write)
    }

    @Test("O_APPEND is a write")
    func appendIsWrite() {
        #expect(accessKind(forOpenFlags: FREAD | Int32(O_APPEND)) == .write)
    }

    @Test("O_TRUNC is a write")
    func truncIsWrite() {
        #expect(accessKind(forOpenFlags: FREAD | Int32(O_TRUNC)) == .write)
    }

    @Test("zero flags classifies as read")
    func zeroIsRead() {
        #expect(accessKind(forOpenFlags: 0) == .read)
    }
}
