#!/bin/bash
set -euo pipefail

# Install a previously downloaded Actions ZIP; never builds or changes the release app.
if [[ $# != 2 ]]; then
  echo "Usage: $0 <artifact.zip> <artifact.zip.sha256>" >&2
  exit 2
fi
zip=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
checksum=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
identity='CodexBar Developer Signing'
keychain="$HOME/Library/Keychains/codexbar-developer-signing.keychain-db"
password='codexbar-developer-signing'
work=$(mktemp -d "${TMPDIR:-/tmp}/codexbar-developer.XXXXXX")
trap 'rm -rf "$work"' EXIT

# Require the checksum to name only this ZIP, and verify before extraction.
expected=$(awk 'NR == 1 {print $1} END {if (NR != 1) exit 1}' "$checksum")
[[ "$expected" =~ ^[[:xdigit:]]{64}$ ]]
actual=$(shasum -a 256 "$zip" | awk '{print $1}')
[[ "$actual" == "$expected" ]] || { echo 'Checksum mismatch' >&2; exit 1; }
/usr/bin/ditto -x -k "$zip" "$work/unpacked"
app="$work/unpacked/CodexBar Developer.app"
plist="$app/Contents/Info.plist"
[[ "$(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$plist")" == com.steipete.codexbar.debug ]]
codesign --verify --deep --strict "$app"

can_sign() {
  local hashes
  hashes=$(security find-certificate -a -c "$identity" -Z "$keychain" | awk '/SHA-1 hash:/ {print $3}')
  [[ "$hashes" =~ ^[[:xdigit:]]{40}$ ]] || return 1
  signing_hash="$hashes"
  cp /bin/echo "$work/probe"
  codesign --force --keychain "$keychain" --sign "$signing_hash" "$work/probe" >/dev/null 2>&1
}
if [[ -e "$keychain" ]]; then
  security unlock-keychain -p "$password" "$keychain"
  can_sign || { echo 'Existing developer keychain cannot sign; refusing to replace it.' >&2; exit 1; }
else
  umask 077
  openssl req -x509 -newkey rsa:2048 -keyout "$work/key.pem" -out "$work/cert.pem" -days 3650 -nodes \
    -subj "/CN=$identity/O=CodexBar" -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=critical,codeSigning' -addext 'basicConstraints=critical,CA:false'
  openssl pkcs12 -export -inkey "$work/key.pem" -in "$work/cert.pem" -out "$work/id.p12" \
    -passout "pass:$password" -name "$identity" -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
  security create-keychain -p "$password" "$keychain"
  security set-keychain-settings "$keychain"
  security unlock-keychain -p "$password" "$keychain"
  security import "$work/id.p12" -k "$keychain" -P "$password" -T /usr/bin/codesign
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null
  rm -f "$work/key.pem" "$work/id.p12"
  # Preserve the existing search list, including entries containing spaces.
  keychains=()
  while IFS= read -r line; do
    line=${line#*\"}; line=${line%\"*}
    [[ -n "$line" && "$line" != "$keychain" ]] && keychains+=("$line")
  done < <(security list-keychains -d user)
  security list-keychains -d user -s "$keychain" "${keychains[@]}"
  can_sign || { echo 'Created identity cannot sign.' >&2; exit 1; }
fi

# Extract original entitlements before replacing signatures. Sign inside out.
codesign -d --entitlements :- "$app" > "$work/app-entitlements.plist" 2>/dev/null
widget="$app/Contents/PlugIns/CodexBarWidget.appex"
codesign -d --entitlements :- "$widget" > "$work/widget-entitlements.plist" 2>/dev/null
source "$(dirname "$0")/sparkle_signing_paths.sh"
sparkle="$app/Contents/Frameworks/Sparkle.framework"
targets=$(codexbar_sparkle_signing_targets "$sparkle")
while IFS= read -r target; do codesign --force --keychain "$keychain" --sign "$signing_hash" "$target"; done <<< "$targets"
for target in "$app/Contents/Helpers/CodexBarCLI" "$app/Contents/Helpers/CodexBar_CodexBarCore.bundle" \
  "$app/Contents/Helpers/CodexBarClaudeWatchdog"; do
  codesign --force --keychain "$keychain" --sign "$signing_hash" "$target"
done
codesign --force --keychain "$keychain" --sign "$signing_hash" --entitlements "$work/widget-entitlements.plist" "$widget/Contents/MacOS/CodexBarWidget"
codesign --force --keychain "$keychain" --sign "$signing_hash" --entitlements "$work/widget-entitlements.plist" "$widget"
codesign --force --keychain "$keychain" --sign "$signing_hash" --entitlements "$work/app-entitlements.plist" "$app"
codesign --verify --deep --strict "$app"
mkdir -p "$HOME/Applications"
destination="$HOME/Applications/CodexBar Developer.app"
if [[ -e "$destination" ]]; then
  [[ "$(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$destination/Contents/Info.plist")" == com.steipete.codexbar.debug ]]
  rm -rf "$destination"
fi
ditto "$app" "$destination"
codesign --verify --deep --strict "$destination"
echo "Installed $destination"
