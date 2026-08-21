# NetExt — Network System Extension (per-process firewall)

This is the `NEFilterDataProvider` content filter for **per-process** connection
filtering using the same macOS mechanism as Little Snitch. It is a real build
target (`PureSnitchNetExt`, `type: system-extension`) embedded only when the
project is generated from `project-netext.yml`; the shipping build excludes it.

## Files
- `main.swift` — entry point (`NEProvider.startSystemExtensionMode()`).
- `FilterDataProvider.swift` — evaluates every new socket flow against the rule
  set, returns allow/drop, or **pauses** the flow and asks the GUI (resuming
  with the user's verdict). Reuses `RuleMatcher` from `Shared/`.
- IPC: `Shared/IPCConnection.swift` (app ↔ extension XPC, modelled on Apple's
  SimpleFirewall sample).
- Rules: `Shared/SharedRuleBridge.swift` — the GUI mirrors the active rules +
  mode into the app-group container; the extension reads them (the extension is
  sandboxed and can't read the helper DB directly).

## What it takes to run (Developer ID, outside the App Store)
1. Enable the **Network Extensions** capability on the App ID in the Apple
   Developer portal (self-serve since 2016 — no email request needed) and add
   the `content-filter-provider-systemextension` entitlement to both the app and
   the extension (declared in `project-netext.yml`, not the shipping
   `project.yml`).
2. Two Developer ID provisioning profiles (app + extension) carrying that
   capability.
3. Sign with **Developer ID Application** (inside-out: extension → helper → app)
   and notarize. The shipping `Scripts/sign_and_notarize.sh` regenerates
   `project.yml`, so use it only as a verification reference, not unchanged.
4. The app must be in **`/Applications`** to activate the extension
   (otherwise `OSSystemExtensionErrorUnsupportedParentBundleLocation`). During
   development you can relax this with `systemextensionsctl developer on`.
5. On first run the user approves it in **System Settings → Privacy & Security**
   (and the network-filter prompt). Activation is driven by
   `GUI/App/SystemExtensionManager.swift`.

The helper (`Sources/Helper`) remains for rule storage, host-wide `pf` rules,
and the experimental loopback DNS proxy used only by manually configured
clients. The system extension is the per-process enforcement layer in this
non-shipping build flavour.
