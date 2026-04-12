//
//  index.swift
//  clearancekit
//

let builtInPresets: [AppPreset] = [
    // App presets — existing
    notesPreset,
    safariPreset,
    mailPreset,
    contactsPreset,
    calendarPreset,
    messagesPreset,
    mullvadPreset,
    heyPreset,
    discordPreset,
    signalPreset,
    chromePreset,
    slackPreset,
    // App presets — new
    firefoxPreset,
    dockerPreset,
    onePassword8Preset,
    onePassword7Preset,
    // System hardening presets (appBundlePath: nil — appear in System Hardening section)
    sshKeysPreset,
    launchItemProtectionPreset,
    cronProtectionPreset,
    passwordHashProtectionPreset,
    keychainProtectionPreset,
    spotlightProtectionPreset,
    audioPluginProtectionPreset,
    inMemoryCodeProtectionPreset,
    awsCredentialProtectionPreset,
]
