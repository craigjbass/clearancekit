//
//  XProtectWatcher.swift
//  opfilter
//
//  Watches the XProtect bundle's MacOS directory via FSEvents and fires
//  a callback when the directory contents change (new remediator added,
//  old one removed, existing one replaced).
//
//  FSEvents coalesces events with the configured latency, so the callback
//  fires once per update burst rather than once per file write.
//

import Foundation
import CoreServices

final class XProtectWatcher {
    static let macOSPath = "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS"
    private static let coalesceLatency: CFTimeInterval = 5.0

    private var stream: FSEventStreamRef?
    private let onChanged: () -> Void

    init(onChanged: @escaping () -> Void) {
        self.onChanged = onChanged
    }

    func start() {
        let paths = [Self.macOSPath] as CFArray
        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        stream = FSEventStreamCreate(
            kCFAllocatorDefault,
            { (_, info, _, _, _, _) in
                guard let info else { return }
                Unmanaged<XProtectWatcher>.fromOpaque(info).takeUnretainedValue().onChanged()
            },
            &context,
            paths,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            Self.coalesceLatency,
            FSEventStreamCreateFlags(kFSEventStreamCreateFlagNone)
        )
        guard let stream else {
            NSLog("XProtectWatcher: Failed to create FSEventStream")
            return
        }
        FSEventStreamSetDispatchQueue(stream, DispatchQueue.global(qos: .utility))
        FSEventStreamStart(stream)
        NSLog("XProtectWatcher: Watching %@", Self.macOSPath)
    }

    deinit {
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
    }
}
