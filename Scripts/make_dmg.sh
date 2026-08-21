#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-0.2.1}"
BUILD_NUMBER="${BUILD_NUMBER:-3}"
APP_BUNDLE="$ROOT/build/release/Build/Products/Release/PureSnitch.app"
DMG_DIR="$ROOT/build/dmg_staging"
DMG="$ROOT/artifacts/PureSnitch-${VERSION}.dmg"
TEAM_ID="H3WXHVTP97"
SIGN_ID="Developer ID Application: Moamen Basel ($TEAM_ID)"
NOTARY_PROFILE="puresnitch-notary"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

plist_value() {
  /usr/libexec/PlistBuddy -c "Print :$2" "$1"
}

assert_plist_metadata() {
  local plist="$1"
  local actual_version actual_build
  actual_version="$(plist_value "$plist" CFBundleShortVersionString)"
  actual_build="$(plist_value "$plist" CFBundleVersion)"
  [ "$actual_version" = "$VERSION" ] || fail "$plist version is $actual_version, expected $VERSION"
  [ "$actual_build" = "$BUILD_NUMBER" ] || fail "$plist build is $actual_build, expected $BUILD_NUMBER"
}

assert_universal() {
  local binary="$1"
  lipo -archs "$binary" | grep -qw arm64 || fail "$binary missing arm64"
  lipo -archs "$binary" | grep -qw x86_64 || fail "$binary missing x86_64"
}

assert_release_signature() {
  local item="$1"
  local signature_info entitlements
  codesign --verify --strict --verbose=2 "$item"
  signature_info="$(codesign -dvv "$item" 2>&1)"
  printf '%s\n' "$signature_info" | grep -Fq "Authority=$SIGN_ID" || fail "$item is not signed by $SIGN_ID"
  printf '%s\n' "$signature_info" | grep -Eq 'flags=.*runtime' || fail "$item is missing hardened runtime"
  entitlements="$(codesign -d --entitlements :- "$item" 2>/dev/null || true)"
  if printf '%s\n' "$entitlements" | grep -A1 '<key>com.apple.security.get-task-allow</key>' | grep -q '<true/>'; then
    fail "$item contains get-task-allow"
  fi
}

mkdir -p artifacts
test -d "$APP_BUNDLE" || fail "$APP_BUNDLE missing - run Scripts/sign_and_notarize.sh first"
assert_plist_metadata "$APP_BUNDLE/Contents/Info.plist"
assert_universal "$APP_BUNDLE/Contents/MacOS/PureSnitch"
assert_universal "$APP_BUNDLE/Contents/MacOS/PureSnitchHelper"
assert_release_signature "$APP_BUNDLE/Contents/MacOS/PureSnitchHelper"
assert_release_signature "$APP_BUNDLE"
codesign --verify --strict --deep --verbose=2 "$APP_BUNDLE"
xcrun stapler validate "$APP_BUNDLE"
rm -rf "$DMG_DIR"
mkdir -p "$DMG_DIR"
# ditto, not cp: it preserves the bundle's metadata and signature intact.
/usr/bin/ditto "$APP_BUNDLE" "$DMG_DIR/PureSnitch.app"
ln -s /Applications "$DMG_DIR/Applications"

rm -f "$DMG"
hdiutil create \
    -volname "PureSnitch ${VERSION}" \
    -srcfolder "$DMG_DIR" \
    -ov \
    -format UDZO \
    -fs HFS+ \
    "$DMG" >/dev/null

echo ">> Signing DMG…"
codesign --force --timestamp --sign "$SIGN_ID" "$DMG"

echo ">> Submitting DMG for notarization…"
xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait

echo ">> Stapling DMG…"
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"
codesign --verify --verbose=2 "$DMG"
hdiutil verify "$DMG" >/dev/null

echo ">> Verifying the artifact users will actually download…"
MOUNT_DIR="$(mktemp -d /tmp/puresnitch-dmg.XXXXXX)"
MOUNT_ATTACHED=0
cleanup_mount() {
  if [ "$MOUNT_ATTACHED" = "1" ]; then
    hdiutil detach "$MOUNT_DIR" -quiet || true
  fi
  rmdir "$MOUNT_DIR" 2>/dev/null || true
}
trap cleanup_mount EXIT INT TERM
hdiutil attach "$DMG" -nobrowse -mountpoint "$MOUNT_DIR" -quiet
MOUNT_ATTACHED=1
INSTALLED="$MOUNT_DIR/PureSnitch.app"
spctl -a -vvv -t exec "$INSTALLED" 2>&1 | sed 's/^/   /'
for BIN in "$INSTALLED/Contents/MacOS/PureSnitch" "$INSTALLED/Contents/MacOS/PureSnitchHelper"; do
  assert_universal "$BIN"
done
test -f "$INSTALLED/Contents/Resources/Assets.car" || fail "no Assets.car in the DMG"
assert_plist_metadata "$INSTALLED/Contents/Info.plist"
assert_release_signature "$INSTALLED/Contents/MacOS/PureSnitchHelper"
assert_release_signature "$INSTALLED"
codesign --verify --strict --deep --verbose=2 "$INSTALLED"
xcrun stapler validate "$INSTALLED"
hdiutil detach "$MOUNT_DIR" -quiet
MOUNT_ATTACHED=0
rmdir "$MOUNT_DIR"
trap - EXIT INT TERM

echo ">> Done: $DMG"
shasum -a 256 "$DMG"
