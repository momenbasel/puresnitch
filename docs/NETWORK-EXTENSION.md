# Why the shipping build has no Network System Extension

`Sources/NetExt` implements a per-process content filter (`NEFilterDataProvider`).
It is not part of the DMG users download, and `project.yml` deliberately omits
these two entitlements from the app:

- `com.apple.developer.networking.networkextension` (`content-filter-provider-systemextension`)
- `com.apple.developer.system-extension.install`

## The reason

Both are *restricted* entitlements. A Developer ID signature does not grant
them. They have to be authorised by an Apple-issued provisioning profile
embedded in the bundle, and AMFI checks that at process creation. Ship a signed
app that requests them without the profile and the failure mode is not a
degraded feature - the process can be refused before `main()` runs, so the app
just never opens.

Two concrete consequences we hit while building the v0.2 series:

- `xcodebuild` refuses outright: *"PureSnitch requires a provisioning profile
  with the Network Extensions and System Extension features."* There is no way
  to produce a signed release with those entitlements and no profile.
- The 0.1.0 users in issue #5 already had an app that looked dead. Shipping a
  build that AMFI can kill at launch would have been a strictly worse bug.

So v0.2.1 ships as a **monitor** with opt-in host-wide `pf` rules: menu bar,
traffic monitor, rules UI, and the privileged helper. The helper also exposes an
experimental loopback DNS proxy for manually configured clients; it does not
change the macOS resolver. There is no system extension or extension approval
prompt in the shipping build.

## Building the firewall flavour

Everything for the extension is still in the tree.

```bash
xcodegen generate --spec project-netext.yml
```

That spec re-adds the entitlements and embeds `PureSnitchNetExt.systemextension`.
Before it can be distributed you need, from the Apple Developer portal:

1. The **Network Extensions** capability enabled on App ID `io.moamenbasel.puresnitch`
   (self-serve) and on `io.moamenbasel.puresnitch.netext`.
2. The **System Extension** capability on the app's App ID.
3. Two Developer ID provisioning profiles - one per App ID - downloaded and
   embedded as `Contents/embedded.provisionprofile` in the respective bundles.
4. A dedicated inside-out signing flow (extension, helper, then app), followed
   by notarization and stapling. `Scripts/sign_and_notarize.sh` is the shipping
   monitor release script and regenerates `project.yml`, so do not use it
   unchanged for this flavour.
5. The app installed in `/Applications` and approved in
   System Settings › Privacy & Security. For local development only,
   `systemextensionsctl developer on` skips the notarization requirement.

Verify before releasing such a build: launch it on a clean machine from
`/Applications`, confirm the extension activates, and confirm nothing appears in
the log as an AMFI/taskgated rejection.
