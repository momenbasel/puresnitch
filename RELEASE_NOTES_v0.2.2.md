# PureSnitch v0.2.2

This is a performance and uninstall-correctness update for the universal
macOS 13+ monitor build.

## Fixed

- The helper and its `nettop` child no longer pin two CPU cores. `nettop` ran
  in continuous mode, which busy-polls at well over a core regardless of the
  sample interval, and the helper resolved every socket's process path by
  spawning `ps` once per connection on every two-second poll. Traffic is now
  sampled once per second from a one-shot `nettop` frame and process paths come
  from `proc_pidpath`; the monitor costs about 0.3% of one core with 160 open
  sockets ([#19](https://github.com/momenbasel/puresnitch/issues/19),
  [#20](https://github.com/momenbasel/puresnitch/pull/20)).
- Traffic rates are diffed per process, so a process closing its sockets no
  longer re-baselines every other process for that interval
  ([#10](https://github.com/momenbasel/puresnitch/issues/10)).
- `brew uninstall --cask puresnitch` with Enforcement on no longer strands the
  `com.apple/puresnitch` anchor. `PureSnitchHelper --cleanup` waits up to 10 s
  for the daemon to exit instead of asserting once, and a helper stopped after
  its bundle is gone releases PF instead of holding state no successor can
  adopt. Dragging the app to the Trash reaches the same clean state through a
  30 s bundle watchdog ([#17](https://github.com/momenbasel/puresnitch/issues/17)).
- In the network-extension flavour, Remove Helper removes the filter
  configuration rather than disabling it, deactivates the system extension only
  after that write completes, and a completed deactivation no longer re-enables
  the filter ([#18](https://github.com/momenbasel/puresnitch/issues/18)). That
  flavour still does not ship; see the limitations below.

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

Turning Enforcement Off and choosing Remove Helper before a Homebrew uninstall
is still the cleanest path. Starting with this release the cask's
`--cleanup` step and the helper's own bundle watchdog cover the case where that
step was skipped.

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
