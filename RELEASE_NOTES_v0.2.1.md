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
- Added a one-time Homebrew upgrade bridge that takes a validated recovery-only
  snapshot before the legacy cask receipt removes its support directory. The
  user-owned snapshot is never promoted automatically into the root helper;
  legacy PF state remains unchanged until the signed app gets an explicit
  Keep On or Turn Off decision.
- Hardened release checks for version/build metadata, universal architectures,
  Developer ID signatures, hardened runtime, notarization, and stapling.
- Corrected Homebrew installation and product documentation.

## Install

```bash
brew trust momenbasel/puresnitch
brew install --cask momenbasel/puresnitch/puresnitch
```

Or download the signed and notarized DMG below and drag PureSnitch into
`/Applications`.

After a Homebrew upgrade, open the signed app promptly and resolve its legacy
firewall prompt. **Decide Later** is the only choice that preserves legacy rules
unchanged. The retained snapshot is recovery-only and is not imported by
v0.2.1; do not copy it into the root support directory or pass it to the helper.
When the current store is empty, **Keep On** is disabled instead of replacing
legacy rules with an empty ruleset. **Turn Off** intentionally removes those
rules. A previous enabled state never auto-approves ruleset replacement. With
**Keep On**, non-default, allow, process-only, domain-only, disabled, expired,
or otherwise non-renderable rules do not survive as host-wide `pf` rules. If
an upgrade rolls back, do not launch the old app before retrying
because it can create new data outside the snapshot.

Before Homebrew uninstall or zap, turn Enforcement Off and choose Remove Helper
inside the signed app. Homebrew deliberately does not alter PF state or delete
the root support database.

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
- Homebrew preserves a full pre-v0.2.1 database snapshot for future signed,
  record-level recovery tooling, but v0.2.1 does not import it automatically.
- Releases before v0.2.1 enabled `pf` without retaining a releasable reference
  token. If legacy enforcement remains enabled after upgrading or uninstalling,
  one Mac restart clears that unrecoverable legacy reference.
