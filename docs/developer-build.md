# Developer builds

Run **Build Developer** from the Actions tab, selecting the desired branch. The workflow checks out the exact dispatch commit, builds an ARM64 debug app and uploads a ZIP and SHA-256 file for seven days. The app's Info.plist records the full source commit (`CodexGitCommit`) and UTC build time (`CodexBuildTimestamp`). The build is ad-hoc signed and is not notarized.

Download both files from the run and install on an Apple Silicon Mac from this repository checkout:

```sh
./Scripts/install_developer.sh ~/Downloads/CodexBar-Developer-macos-arm64-<sha>.zip ~/Downloads/CodexBar-Developer-macos-arm64-<sha>.zip.sha256
open "$HOME/Applications/CodexBar Developer.app"
```

The installer verifies the checksum and original signature, creates a local self-signed identity once, signs the nested code and app with their entitlements, and verifies the installed bundle. It reuses the keychain on later runs and refuses to replace an existing identity that cannot sign. The private key stays on the Mac; temporary key material is removed after import. Keep the keychain to preserve the signing identity across updates. If macOS retains a stale permission after moving from an earlier ad-hoc installation, remove that app's entry in System Settings and grant it again. Local signing is not notarization; macOS may require an explicit first-launch approval in Privacy & Security.

The Developer app has its own bundle ID, settings and app data and does not use the production Sparkle feed. It installs separately from `/Applications/CodexBar.app`. Provider applications and browser sessions remain external data sources and may still request normal macOS permission.
