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
VERSION="${VERSION:-0.2.0}"
NOTARIZE="${NOTARIZE:-1}"

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
xcodebuild -project PureSnitch.xcodeproj -scheme PureSnitch -configuration Release \
  -derivedDataPath build/release \
  ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO \
  CODE_SIGN_IDENTITY="$SIGN_ID" CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM="$TEAM_ID" \
  OTHER_CODE_SIGN_FLAGS="--timestamp --options=runtime" build > build/release/xcodebuild.log 2>&1

if [ ! -d "$APP_BUNDLE" ]; then
    echo "ERROR: $APP_BUNDLE missing"
    tail -50 build/release/xcodebuild.log
    exit 1
fi

echo ">> Verifying the bundle a user actually gets…"
HELPER_BIN="$APP_BUNDLE/Contents/MacOS/PureSnitchHelper"
test -f "$HELPER_BIN" || { echo "ERROR: privileged helper missing from the bundle"; exit 1; }
test -f "$APP_BUNDLE/Contents/Library/LaunchDaemons/io.moamenbasel.puresnitch.helper.plist" || { echo "ERROR: launchd plist missing"; exit 1; }
test -f "$APP_BUNDLE/Contents/Resources/Assets.car" || { echo "ERROR: Assets.car missing - the app would have no icon"; exit 1; }
test -f "$APP_BUNDLE/Contents/Resources/AppIcon.icns" || { echo "ERROR: AppIcon.icns missing"; exit 1; }
for BIN in "$APP_BUNDLE/Contents/MacOS/PureSnitch" "$HELPER_BIN"; do
  lipo -archs "$BIN" | grep -qw arm64   || { echo "ERROR: $BIN has no arm64 slice"; exit 1; }
  lipo -archs "$BIN" | grep -qw x86_64  || { echo "ERROR: $BIN has no x86_64 slice"; exit 1; }
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
codesign --verify --strict --deep --verbose=2 "$APP_BUNDLE"

echo ">> Zipping for notarization…"
ZIP="artifacts/PureSnitch-${VERSION}-notary.zip"
rm -f "$ZIP"
/usr/bin/ditto -c -k --keepParent "$APP_BUNDLE" "$ZIP"

if [ "$NOTARIZE" = "1" ]; then
  echo ">> Submitting to Apple notary…"
  xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait

  echo ">> Stapling notary ticket…"
  xcrun stapler staple "$APP_BUNDLE"
  xcrun stapler validate "$APP_BUNDLE"
else
  echo ">> NOTARIZE=0 - skipping notarization (app will be Gatekeeper-blocked on other Macs)"
fi

echo ">> Done. Notarized app at $APP_BUNDLE"
