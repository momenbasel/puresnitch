# Contributing to PureSnitch

Thanks for considering a contribution. The bar is: ship working code, keep the diff small, leave the codebase clearer than you found it.

## Quick start

```bash
git clone https://github.com/momenbasel/puresnitch.git
cd puresnitch
brew install xcodegen
xcodegen generate
open PureSnitch.xcodeproj
```

The project file carries the maintainer's release-signing identity. For a
certificate-free local build, use:

```bash
xcodebuild -project PureSnitch.xcodeproj -scheme PureSnitch -configuration Debug \
  -derivedDataPath build/dd \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO \
  build
```

That build launches the GUI, but it cannot register the privileged helper and
therefore has no live monitoring or enforcement. Configure your own Developer
ID signing when testing helper-backed behavior.

## Conventions

- **Swift 5**, macOS 13 (Ventura)+ deployment target.
- **No new dependencies** unless there's a load-bearing reason. SQLite via `import SQLite3` is fine; a third-party Swift package needs justification in the PR.
- **f-strings? no.** This is Swift. String interpolation, not Python.
- **No emoji in code or commits.** Yes, even there.
- **Match the existing style.** SwiftUI views split into small private computed properties. No mega-views.
- **Comments are for *why*, not *what*.** Identifier names should carry the *what*.

## Areas where help is most welcome

1. **Network Extension path** (Sources/NetExt/). If you have access to the `com.apple.developer.networking.networkextension` entitlement and want to wire up true per-process filtering, this is the highest-impact contribution.
2. **macOS 15 / 16 / 26 compatibility**. Test on every macOS you have, report breakage with a paste of the build error.
3. **Localization**. The strings are not yet `.strings`-extracted. Help wanted.
4. **Blocklist curation**. Add high-quality, low-false-positive lists; remove anything stale.
5. **UI polish**. Pixel-level fidelity to Little Snitch is the bar. Submit screenshots in the PR.

## Pull request checklist

- [ ] Builds clean with the certificate-free command above
- [ ] No new warnings in your changed files
- [ ] Manual test pass: app launches, menubar popover appears, Network Monitor opens, Rules Manager opens
- [ ] If you touched the helper: `sudo lsof -nP -iUDP:53` shows only the loopback listener, and `sudo pfctl -a com.apple/puresnitch -s rules` shows only PureSnitch's validated runtime rules

## Reporting bugs

Open an issue. Include:
- macOS version
- PureSnitch version (Settings → About)
- Reproduction steps
- Console output from `log stream --predicate 'subsystem == "io.moamenbasel.puresnitch"'`

## License

By contributing you agree your contributions are licensed under the MIT License.
