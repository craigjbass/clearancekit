//
//  TTYNotifier.swift
//  opfilter
//

import Foundation

// MARK: - TTYNotifier

struct TTYNotifier {
    func writeDenial(path: String, ttyPath: String?) {
        guard let ttyPath, let fh = FileHandle(forWritingAtPath: ttyPath) else { return }
        let msg = "\n⛔️ Access denied to \(path) by ClearanceKit. See the app for details.\n"
        if let data = msg.data(using: .utf8) {
            fh.write(data)
        }
        let fd = fh.fileDescriptor
        let pgrp = tcgetpgrp(fd)
        if pgrp > 0 {
            killpg(pgrp, SIGWINCH)
        }
        fh.closeFile()
    }
}
