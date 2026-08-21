#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APP_BUNDLE="build/release/Build/Products/Release/PureSnitch.app"
TEAM_ID="H3WXHVTP97"
SIGN_ID="Developer ID Application: Moamen Basel ($TEAM_ID)"
NOTARY_PROFILE="puresnitch-notary"
APP_ENT="$ROOT/Sources/GUI/PureSnitch.entitlements"
HELPER_ENT="$ROOT/Sources/Helper/Helper.entitlements"
NETEXT_ENT="$ROOT/Sources/NetExt/NetExt.entitlements"
VERSION="${VERSION:-0.2.1}"
BUILD_NUMBER="${BUILD_NUMBER:-3}"
NOTARIZE="${NOTARIZE:-1}"

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
  lipo -archs "$binary" | grep -qw arm64 || fail "$binary has no arm64 slice"
  lipo -archs "$binary" | grep -qw x86_64 || fail "$binary has no x86_64 slice"
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

for SOURCE_PLIST in \
  "$ROOT/Sources/GUI/Info.plist" \
  "$ROOT/Sources/Helper/Info.plist" \
  "$ROOT/Sources/NetExt/Info.plist"; do
  assert_plist_metadata "$SOURCE_PLIST"
done

echo ">> Cleaning previous build…"
rm -rf build/release
mkdir -p artifacts

echo ">> Regenerating the Xcode project (it is not tracked in git)…"
xcodegen generate

echo ">> Building Release (universal)…"
mkdir -p build/release
# ARCHS must be passed on the command line: the project-level setting alone
# still produced an arm64-only binary, which is how v0.1.0 shipped without an
# Intel slice and simply refused to launch on Intel Macs.
if ! xcodebuild -project PureSnitch.xcodeproj -scheme PureSnitch -configuration Release \
  -derivedDataPath build/release \
  ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO \
  CODE_SIGN_IDENTITY="$SIGN_ID" CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM="$TEAM_ID" \
  OTHER_CODE_SIGN_FLAGS="--timestamp --options=runtime" build > build/release/xcodebuild.log 2>&1; then
  tail -50 build/release/xcodebuild.log
  fail "Release build failed"
fi

[ -d "$APP_BUNDLE" ] || fail "$APP_BUNDLE missing"

echo ">> Verifying the bundle a user actually gets…"
HELPER_BIN="$APP_BUNDLE/Contents/MacOS/PureSnitchHelper"
assert_plist_metadata "$APP_BUNDLE/Contents/Info.plist"
test -f "$HELPER_BIN" || fail "privileged helper missing from the bundle"
test -f "$APP_BUNDLE/Contents/Library/LaunchDaemons/io.moamenbasel.puresnitch.helper.plist" || fail "launchd plist missing"
test -f "$APP_BUNDLE/Contents/Resources/Assets.car" || fail "Assets.car missing - the app would have no icon"
test -f "$APP_BUNDLE/Contents/Resources/AppIcon.icns" || fail "AppIcon.icns missing"
for BIN in "$APP_BUNDLE/Contents/MacOS/PureSnitch" "$HELPER_BIN"; do
  assert_universal "$BIN"
done
echo "   universal + icon + helper OK"

echo ">> Stripping duplicate helper from Resources/ if any…"
rm -f "$APP_BUNDLE/Contents/Resources/PureSnitchHelper"

echo ">> Re-signing helper without get-task-allow…"
HELPER="$APP_BUNDLE/Contents/MacOS/PureSnitchHelper"
codesign --remove-signature "$HELPER" || true
codesign --force --options=runtime --timestamp \
  --entitlements "$HELPER_ENT" \
  --sign "$SIGN_ID" \
  "$HELPER"

echo ">> Re-signing network system extension…"
NETEXT="$APP_BUNDLE/Contents/Library/SystemExtensions/PureSnitchNetExt.systemextension"
if [ -d "$NETEXT" ]; then
  codesign --remove-signature "$NETEXT" || true
  codesign --force --options=runtime --timestamp \
    --entitlements "$NETEXT_ENT" \
    --sign "$SIGN_ID" \
    "$NETEXT"
else
  echo "warning: system extension not found, skipping"
fi

echo ">> Re-signing app without get-task-allow…"
codesign --remove-signature "$APP_BUNDLE" || true
codesign --force --options=runtime --timestamp \
  --entitlements "$APP_ENT" \
  --sign "$SIGN_ID" \
  "$APP_BUNDLE"

echo ">> Verifying signatures…"
assert_release_signature "$HELPER"
assert_release_signature "$APP_BUNDLE"
codesign --verify --strict --deep --verbose=2 "$APP_BUNDLE"

if [ "$NOTARIZE" = "1" ]; then
  echo ">> Zipping for notarization…"
  # The ZIP is transient notarization input under build/. Only the final DMG
  # belongs in artifacts/ and should be attached to the GitHub release.
  NOTARY_ZIP="$ROOT/build/release/PureSnitch-${VERSION}-notary.zip"
  rm -f "$NOTARY_ZIP"
  /usr/bin/ditto -c -k --keepParent "$APP_BUNDLE" "$NOTARY_ZIP"

  echo ">> Submitting to Apple notary…"
  xcrun notarytool submit "$NOTARY_ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
  rm -f "$NOTARY_ZIP"

  echo ">> Stapling notary ticket…"
  xcrun stapler staple "$APP_BUNDLE"
  xcrun stapler validate "$APP_BUNDLE"
  spctl -a -vvv -t exec "$APP_BUNDLE"
else
  echo ">> NOTARIZE=0 - skipping notarization (app will be Gatekeeper-blocked on other Macs)"
fi

echo ">> Done. Release app at $APP_BUNDLE"
