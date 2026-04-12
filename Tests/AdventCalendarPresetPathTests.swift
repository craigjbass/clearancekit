//
//  AdventCalendarPresetPathTests.swift
//  clearancekitTests
//
//  Characterises pathIsProtected coverage for each path pattern introduced
//  by the Advent Calendar presets. Guards against typos in prefix patterns.
//

import Testing
import Foundation

@Suite("Advent Calendar preset path coverage")
struct AdventCalendarPresetPathTests {

    // MARK: - Safari cookie fix (Day 6)

    @Test("Safari Cookies.binarycookies path is protected")
    func safariCookiesPathProtected() {
        #expect(pathIsProtected("/Users/alice/Library/Cookies/Cookies.binarycookies",
                                by: "/Users/*/Library/Cookies/Cookies.binarycookies"))
    }

    @Test("Safari cookie rule does not protect other cookie files")
    func safariCookiesRuleDoesNotProtectOtherFiles() {
        #expect(!pathIsProtected("/Users/alice/Library/Cookies/com.example.app.binarycookies",
                                 by: "/Users/*/Library/Cookies/Cookies.binarycookies"))
    }

    // MARK: - Firefox (Day 6)

    @Test("Firefox profile directory is protected")
    func firefoxProfileProtected() {
        #expect(pathIsProtected("/Users/alice/Library/Application Support/Firefox/Profiles/abc123.default/cookies.sqlite",
                                by: "/Users/*/Library/Application Support/Firefox"))
    }

    @Test("Firefox cache directory is protected")
    func firefoxCacheProtected() {
        #expect(pathIsProtected("/Users/alice/Library/Caches/Firefox/Profiles/abc123.default/cache2",
                                by: "/Users/*/Library/Caches/Firefox"))
    }

    // MARK: - Docker (Day 16)

    @Test("Docker group container is protected")
    func dockerGroupContainerProtected() {
        #expect(pathIsProtected("/Users/alice/Library/Group Containers/group.com.docker/configuration.json",
                                by: "/Users/*/Library/Group Containers/group.com.docker"))
    }

    @Test("Docker CLI config is protected")
    func dockerCLIConfigProtected() {
        #expect(pathIsProtected("/Users/alice/.docker/config.json",
                                by: "/Users/*/.docker"))
    }

    // MARK: - 1Password (Day 17)

    @Test("1Password 8 group container is protected")
    func onePassword8GroupContainerProtected() {
        #expect(pathIsProtected("/Users/alice/Library/Group Containers/2BUA8C4S2C.com.agilebits/vault.sqlite",
                                by: "/Users/*/Library/Group Containers/2BUA8C4S2C.com.agilebits"))
    }

    // MARK: - SSH keys (Day 19)

    @Test("SSH key directory is protected")
    func sshKeyDirectoryProtected() {
        #expect(pathIsProtected("/Users/alice/.ssh/id_ed25519",
                                by: "/Users/*/.ssh"))
    }

    @Test("SSH public key is also protected by write-only rule")
    func sshPublicKeyProtected() {
        #expect(pathIsProtected("/Users/alice/.ssh/id_ed25519.pub",
                                by: "/Users/*/.ssh"))
    }

    // MARK: - Launch items (Day 12)

    @Test("user LaunchAgents directory is protected")
    func userLaunchAgentsProtected() {
        #expect(pathIsProtected("/Users/alice/Library/LaunchAgents/com.example.backdoor.plist",
                                by: "/Users/*/Library/LaunchAgents"))
    }

    @Test("system LaunchDaemons directory is protected")
    func systemLaunchDaemonsProtected() {
        #expect(pathIsProtected("/Library/LaunchDaemons/com.example.daemon.plist",
                                by: "/Library/LaunchDaemons"))
    }

    // MARK: - Cron (Day 13)

    @Test("cron at-jobs directory is protected")
    func cronAtJobsProtected() {
        #expect(pathIsProtected("/private/var/at/jobs/a00019ddd8d0a1",
                                by: "/private/var/at"))
    }

    @Test("cron lib directory is protected")
    func cronLibProtected() {
        #expect(pathIsProtected("/usr/lib/cron/tabs/alice",
                                by: "/usr/lib/cron"))
    }

    // MARK: - Password hashes (Day 8)

    @Test("dslocal users directory is protected")
    func dsLocalUsersProtected() {
        #expect(pathIsProtected("/var/db/dslocal/nodes/Default/users/alice.plist",
                                by: "/var/db/dslocal/nodes/Default/users"))
    }

    // MARK: - Keychain (Day 9)

    @Test("user Keychains directory is protected")
    func userKeychainsProtected() {
        #expect(pathIsProtected("/Users/alice/Library/Keychains/login.keychain-db",
                                by: "/Users/*/Library/Keychains"))
    }

    @Test("system Keychains directory is protected")
    func systemKeychainsProtected() {
        #expect(pathIsProtected("/Library/Keychains/System.keychain",
                                by: "/Library/Keychains"))
    }

    // MARK: - Spotlight importer (Day 18)

    @Test("user Spotlight directory is protected")
    func spotlightDirectoryProtected() {
        #expect(pathIsProtected("/Users/alice/Library/Spotlight/malicious.mdimporter",
                                by: "/Users/*/Library/Spotlight"))
    }

    // MARK: - Audio plugins (Day 22)

    @Test("audio components directory is protected")
    func audioComponentsProtected() {
        #expect(pathIsProtected("/Library/Audio/Plug-Ins/Components/Backdoor.component",
                                by: "/Library/Audio/Plug-Ins/Components"))
    }

    @Test("audio HAL directory is protected")
    func audioHALProtected() {
        #expect(pathIsProtected("/Library/Audio/Plug-Ins/HAL/Spyware.driver",
                                by: "/Library/Audio/Plug-Ins/HAL"))
    }

    // MARK: - In-memory code loading (Day 15)

    @Test("NSCreateObjectFileImageFromMemory temp files are protected")
    func inMemoryCodeLoadingProtected() {
        #expect(pathIsProtected(
            "/private/var/folders/zz/zyxvpxvq6csfxvn_n00000sm00006d/T/NSCreateObjectFileImageFromMemory-12345",
            by: "/private/var/folders/**/NSCreateObjectFileImageFromMemory-*"
        ))
    }

    @Test("normal temp files are not caught by in-memory rule")
    func normalTempFilesNotCaught() {
        #expect(!pathIsProtected(
            "/private/var/folders/zz/zyxvpxvq6csfxvn_n00000sm00006d/T/com.apple.launchd.tmp",
            by: "/private/var/folders/**/NSCreateObjectFileImageFromMemory-*"
        ))
    }

    // MARK: - AWS credentials (Day 25)

    @Test("AWS credentials file is protected")
    func awsCredentialsProtected() {
        #expect(pathIsProtected("/Users/alice/.aws/credentials",
                                by: "/Users/*/.aws/credentials"))
    }

    @Test("AWS credentials rule does not protect other aws files")
    func awsCredentialsRuleDoesNotProtectOtherFiles() {
        #expect(!pathIsProtected("/Users/alice/.aws/cli/cache/token.json",
                                 by: "/Users/*/.aws/credentials"))
    }

    @Test("AWS config file is protected by write-only rule")
    func awsConfigProtected() {
        #expect(pathIsProtected("/Users/alice/.aws/config",
                                by: "/Users/*/.aws/config"))
    }

    // MARK: - PAM built-in rule (Day 11)

    @Test("PAM directory is covered by built-in faaPolicy rule")
    func pamRuleInBuiltinPolicy() {
        let pamRule = faaPolicy.first { $0.protectedPathPrefix == "/etc/pam.d" }
        #expect(pamRule != nil)
        #expect(pamRule?.source == .builtin)
        #expect(pamRule?.enforceOnWriteOnly == true)
    }

    @Test("PAM rule path covers pam.d files")
    func pamRuleCoversFiles() {
        #expect(pathIsProtected("/etc/pam.d/sudo", by: "/etc/pam.d"))
        #expect(pathIsProtected("/etc/pam.d/login", by: "/etc/pam.d"))
    }
}
