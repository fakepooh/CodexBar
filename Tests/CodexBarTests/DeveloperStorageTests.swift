import Foundation
import Testing
@testable import CodexBarCore

struct DeveloperStorageTests {
    @Test
    func `only developer app and widget identifiers use developer storage`() {
        #expect(DeveloperStorage.isDeveloperBundleID("com.steipete.codexbar.debug"))
        #expect(DeveloperStorage.isDeveloperBundleID("com.steipete.codexbar.debug.widget"))
        #expect(!DeveloperStorage.isDeveloperBundleID("com.steipete.codexbar"))
        #expect(!DeveloperStorage.isDeveloperBundleID(nil))
        #expect(!DeveloperStorage.isDeveloperBundleID("com.steipete.codexbar.debug.other"))
        #expect(DeveloperStorage.directoryName(isDeveloper: true) == "CodexBar Developer")
        #expect(DeveloperStorage.directoryName(isDeveloper: false) == "CodexBar")
    }

    @Test
    func `developer plugins use a separate writable directory`() {
        let home = URL(fileURLWithPath: "/tmp/developer-fixture", isDirectory: true)
        #expect(UserProviderPluginLoader.providersDirectory(home: home, isDeveloper: true).path
            == "/tmp/developer-fixture/.config/codexbar-developer/providers")
        #expect(UserProviderPluginLoader.providersDirectory(home: home, isDeveloper: false).path
            == "/tmp/developer-fixture/.config/codexbar/providers")
    }

    @Test
    func `developer configuration uses a separate path and honors explicit overrides`() {
        let home = URL(fileURLWithPath: "/tmp/developer-fixture", isDirectory: true)
        let path = CodexBarConfigStore.defaultURL(home: home, environment: [:], isDeveloper: true)
        #expect(path.path == "/tmp/developer-fixture/.codexbar-developer/config.json")
        let override = CodexBarConfigStore.defaultURL(
            home: home,
            environment: ["CODEXBAR_CONFIG": "/tmp/explicit.json"],
            isDeveloper: true)
        #expect(override.path == "/tmp/explicit.json")
    }
}
