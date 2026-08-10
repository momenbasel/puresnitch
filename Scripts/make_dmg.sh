#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-0.2.0}"
APP_BUNDLE="$ROOT/build/release/Build/Products/Release/PureSnitch.app"
DMG_DIR="$ROOT/build/dmg_staging"
DMG="$ROOT/artifacts/PureSnitch-${VERSION}.dmg"
TEAM_ID="H3WXHVTP97"
SIGN_ID="Developer ID Application: Moamen Basel ($TEAM_ID)"
NOTARY_PROFILE="puresnitch-notary"

mkdir -p artifacts
test -d "$APP_BUNDLE" || { echo "ERROR: $APP_BUNDLE missing - run Scripts/sign_and_notarize.sh first"; exit 1; }
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

echo ">> Verifying the artifact users will actually download…"
MNT="$(mktemp -d)"
hdiutil attach "$DMG" -nobrowse -mountpoint "$MNT" -quiet
INSTALLED="$MNT/PureSnitch.app"
spctl -a -vvv -t exec "$INSTALLED" 2>&1 | sed 's/^/   /'
for BIN in "$INSTALLED/Contents/MacOS/PureSnitch" "$INSTALLED/Contents/MacOS/PureSnitchHelper"; do
  lipo -archs "$BIN" | grep -qw arm64  || { hdiutil detach "$MNT" -quiet; echo "ERROR: $BIN missing arm64"; exit 1; }
  lipo -archs "$BIN" | grep -qw x86_64 || { hdiutil detach "$MNT" -quiet; echo "ERROR: $BIN missing x86_64"; exit 1; }
done
test -f "$INSTALLED/Contents/Resources/Assets.car" || { hdiutil detach "$MNT" -quiet; echo "ERROR: no Assets.car in the DMG"; exit 1; }
/usr/libexec/PlistBuddy -c "Print :LSMinimumSystemVersion" "$INSTALLED/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$INSTALLED/Contents/Info.plist"
xcrun stapler validate "$INSTALLED" || echo "   (app not stapled - only the DMG is)"
hdiutil detach "$MNT" -quiet
rmdir "$MNT" 2>/dev/null || true

echo ">> Done: $DMG"
shasum -a 256 "$DMG"
