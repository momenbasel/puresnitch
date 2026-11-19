# PureSnitch v0.2.3

This is a blocklist fix for the universal macOS 13+ monitor build.

## Fixed

- The malware blocklist enabled by default loaded nothing. abuse.ch retired the
  keyless URLhaus downloads and the hostfile URL now answers 410. It is replaced
  by HaGeZi Threat Intelligence Feeds (mini), served from the same GitLab mirror
  as HaGeZi Multi Light and parsed by the existing Adblock reader (about 209,000
  hosts). Upgrades keep the on/off choice made for URLhaus, and a URLhaus entry
  whose URL was edited by hand is left alone
  ([#22](https://github.com/momenbasel/puresnitch/pull/22)).

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

## Current limitations

The limitations listed in the
[v0.2.2 notes](https://github.com/momenbasel/puresnitch/releases/tag/v0.2.2)
are unchanged.
