//
//  AccessKindClassifier.swift
//  opfilter
//
//  Classifies an Endpoint Security AUTH_OPEN request as a read or a write.
//  The kernel-level fflag bitfield delivered with the event encodes the
//  caller's intent — see open(2) and <sys/fcntl.h>. Any of FWRITE, O_APPEND,
//  or O_TRUNC means the open will (or may) modify the file, so the request
//  is classified as a write.
//

import Foundation

func accessKind(forOpenFlags fflag: Int32) -> AccessKind {
    let writeFlags: Int32 = FWRITE | Int32(O_APPEND) | Int32(O_TRUNC)
    return (fflag & writeFlags) != 0 ? .write : .read
}
