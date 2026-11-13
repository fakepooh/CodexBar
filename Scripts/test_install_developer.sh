#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/codexbar-developer-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
printf 'not a zip' > "$tmp/artifact.zip"
printf '%064d  artifact.zip\n' 0 > "$tmp/artifact.zip.sha256"
if "$root/Scripts/install_developer.sh" "$tmp/artifact.zip" "$tmp/artifact.zip.sha256" >"$tmp/log" 2>&1; then
  echo 'Incorrect checksum was accepted' >&2
  exit 1
fi
grep -q 'Checksum mismatch' "$tmp/log"
echo 'Developer installer rejects an incorrect checksum before extraction or Keychain access.'
