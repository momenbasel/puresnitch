# PureSnitch v0.2.1

This is a safety and release-reliability update for the universal macOS 13+
monitor build.

## Fixed

- Added explicit Xcode product and module names for Xcode 27 compatibility
  ([#11](https://github.com/momenbasel/puresnitch/pull/11)).
- Updated the HaGeZi blocklist source, migrated the retired built-in URL without
  overwriting custom URLs, rejected invalid responses, and retained
  last-known-good blocklists when refreshes fail
  ([#13](https://github.com/momenbasel/puresnitch/pull/13)).
- Restricted the experimental DNS listener to loopback and bounded pending DNS
  prompts with independent IDs, timeouts, capacity limits, and shutdown cleanup.
- Replaced legacy `/etc/pf.conf` mutation with an isolated runtime
  `com.apple/puresnitch` anchor, reference-token cleanup, and exact legacy-state
  migration. Disable failures remain visible and preserve conservative state.
- Validated rule input before writing the root-owned `pf` anchor and rejected
  invalid IPv4 CIDR prefix lengths.
- Synchronized the active helper mode back to the GUI.
- Reused stable IDs for continuously observed sockets and capped retained
  connection history at the newest 5,000 rows, preventing the legacy
  two-second snapshots from growing the database without bound.
- Restricted helper XPC access to the administrator who claimed it from the
  active console, re-authorized every request, and protected helper state with
  root-only permissions. Helper-owned enforcement state now survives process
  restarts.
- Gated the legacy `pf` handover behind an explicit in-app decision. When the
  helper reports preserved legacy state, the app leaves it untouched until the
  user picks Keep On or Turn Off; a previously enabled state is never treated
  as approval, and Keep On is refused outright when the current rule store is
  empty.
- Hardened release checks for version/build metadata, universal architectures,
  Developer ID signatures, hardened runtime, notarization, and stapling.
- Corrected Homebrew installation and product documentation.

## Install

```bash
brew tap momenbasel/puresnitch
brew trust --tap momenbasel/puresnitch
brew install --cask puresnitch
```

Homebrew 6 refuses to load casks from an untrusted third-party tap, which is why
the `brew trust` line is required once. Upgrade later with
`brew upgrade --cask puresnitch`.

Or download the signed and notarized DMG below and drag PureSnitch into
`/Applications`.

After upgrading from v0.1.0 or v0.2.0, open the app once and resolve its legacy
firewall prompt. **Decide Later** is the default and the only choice that
preserves legacy rules unchanged. When the current store is empty, **Keep On**
is disabled instead of replacing legacy rules with an empty ruleset. **Turn
Off** intentionally removes those rules. A previous enabled state never
auto-approves ruleset replacement. With **Keep On**, non-default, allow,
process-only, domain-only, disabled, expired, or otherwise non-renderable rules
do not survive as host-wide `pf` rules.

Before Homebrew uninstall or zap, turn Enforcement Off and choose Remove Helper
inside the app. Homebrew deliberately does not alter PF state or delete the
root support database.

## Current limitations

- The shipping build does not include per-process Network Extension filtering;
  that path still requires Apple-issued provisioning profiles.
- DNS filtering is an experimental loopback proxy for clients configured
  manually. PureSnitch does not change the macOS system resolver.
- Alert decisions can pause only DNS requests sent to that proxy. Passively
  observed app sockets are not paused without the non-shipping Network Extension.
- Only the Default profile is enforced. Other profiles are organizational
  labels, and SSID-based switching is not implemented.
- Persistent `pf` enforcement is IPv4-only and host-wide. IPv6 alert decisions
  are one-time; per-process, domain, and allow rules are not emitted to `pf`.
- Traffic totals are process aggregates. Per-connection byte accounting and
  live IP geolocation are not included in this release.
- Homebrew does not snapshot or restore the root-owned rule database. It is
  left in place on uninstall precisely so nothing outside the signed app can
  rewrite live firewall state.
- Releases before v0.2.1 enabled `pf` without retaining a releasable reference
  token. If legacy enforcement remains enabled after upgrading or uninstalling,
  one Mac restart clears that unrecoverable legacy reference.
