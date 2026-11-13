import Foundation

/// Separates developer app state from the released app, including bundled helpers.
public enum DeveloperStorage {
    public static let isDeveloper: Bool = {
        if DeveloperStorage.isDeveloperBundleID(Bundle.main.bundleIdentifier) { return true }
        guard let executable = Bundle.main.executableURL else { return false }
        var directory = executable.deletingLastPathComponent()
        for _ in 0..<6 {
            if directory.pathExtension == "app",
               DeveloperStorage.isDeveloperBundleID(Bundle(url: directory)?.bundleIdentifier)
            {
                return true
            }
            directory.deleteLastPathComponent()
        }
        return false
    }()

    static func isDeveloperBundleID(_ identifier: String?) -> Bool {
        identifier == "com.steipete.codexbar.debug" || identifier == "com.steipete.codexbar.debug.widget"
    }

    static func directoryName(isDeveloper: Bool) -> String { isDeveloper ? "CodexBar Developer" : "CodexBar" }

    public static var directoryName: String {
        self.directoryName(isDeveloper: self.isDeveloper)
    }

    public static var bundleDirectoryName: String {
        self.isDeveloper ? "com.steipete.codexbar.debug" : "com.steipete.codexbar"
    }

    public static var dotDirectoryName: String {
        self.isDeveloper ? ".codexbar-developer" : ".codexbar"
    }
}
