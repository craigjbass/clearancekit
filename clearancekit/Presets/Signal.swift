//
//  Signal.swift
//  clearancekit
//

let signalPreset = AppPreset(
    id: "signal-data-protection",
    appName: "Signal",
    appBundlePath: "/Applications/Signal.app",
    description: "Prevents other processes from reading Signal's local messages and attachments. Only Signal and its helpers may open files in its application support directory.",
    rules: [
        FAARule(
            id: UUID(uuidString: "D8D8D470-643F-41F3-8BF0-00D390002311")!,
            protectedPathPrefix: "/Users/*/Library/Application Support/Signal",
            allowedSignatures: [
                sig("U68MSDN6DR", "org.whispersystems.signal-desktop"),
                sig("U68MSDN6DR", "org.whispersystems.signal-desktop.helper.Renderer"),
                sig("U68MSDN6DR", "org.whispersystems.signal-desktop.helper"),
            ]
        ),
    ]
)
