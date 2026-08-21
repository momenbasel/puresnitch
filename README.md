<p align="center">
  <img src="screenshot.png" alt="PureSnitch — open-source macOS application firewall" width="800">
</p>

<p align="center">
  <b>English</b> |
  <a href="docs/README.ar.md">العربية</a> |
  <a href="docs/README.es.md">Español</a> |
  <a href="docs/README.ja.md">日本語</a> |
  <a href="docs/README.zh-Hans.md">简体中文</a> |
  <a href="docs/README.zh-Hant.md">繁體中文</a>
</p>

<h1 align="center">PureSnitch</h1>

<p align="center">
  <b>See what your Mac is talking to. Block what you don't trust.</b><br>
  Free, open-source application firewall for macOS. No subscription, no telemetry, no upsell.
</p>

<p align="center">
  <a href="https://github.com/momenbasel/puresnitch/releases/latest"><img src="https://img.shields.io/github/v/release/momenbasel/puresnitch?style=flat-square&label=Download" alt="Latest Release"></a>
  <img src="https://img.shields.io/badge/macOS-13.0+-blue?style=flat-square" alt="macOS 13.0+">
  <img src="https://img.shields.io/badge/Swift-5-orange?style=flat-square" alt="Swift 5">
  <img src="https://img.shields.io/badge/Notarized-Apple-success?style=flat-square" alt="Notarized">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/momenbasel/puresnitch?style=flat-square" alt="MIT License"></a>
  <a href="https://github.com/momenbasel/puresnitch/stargazers"><img src="https://img.shields.io/github/stars/momenbasel/puresnitch?style=flat-square" alt="Stars"></a>
  <a href="https://github.com/momenbasel/puresnitch/releases"><img src="https://img.shields.io/github/downloads/momenbasel/puresnitch/total?style=flat-square&label=Downloads" alt="Downloads"></a>
</p>

<p align="center">
  <a href="#install">Install</a> -
  <a href="#why-this-exists">Why this exists</a> -
  <a href="#what-it-does">What it does</a> -
  <a href="#how-it-works">How it works</a> -
  <a href="#permissions">Permissions</a> -
  <a href="#screenshots">Screenshots</a> -
  <a href="#contributing">Contributing</a>
</p>

---

## Install

```bash
brew trust momenbasel/puresnitch
brew install --cask momenbasel/puresnitch/puresnitch
```

Homebrew 6 requires explicit trust before it evaluates third-party tap code.
The tap contains the PureSnitch cask and its one-time upgrade migration formula.

For upgrades from a pre-v0.2.1 cask, the tap takes a validated recovery-only
snapshot before Homebrew removes the old support directory. That user-owned
snapshot is never restored automatically or trusted as root firewall state;
do not copy it into `/Library/Application Support/PureSnitch` or pass it to the
helper. Open the signed app promptly after upgrading. **Decide Later** is the
only choice that preserves legacy rules unchanged. If the current v0.2.1 rule
store is empty, **Keep On** is disabled rather than replacing those rules with
an empty ruleset; **Turn Off** intentionally removes them. A previous enabled
state never auto-approves this replacement. With **Keep On**, non-default,
allow, process-only, domain-only, disabled, expired, or otherwise non-renderable
rules do not survive as host-wide `pf` rules.

Before `brew uninstall` or `brew uninstall --zap`, turn Enforcement Off and
choose Remove Helper in the signed app. Homebrew intentionally does not mutate
PF state or delete the root support database during uninstall.

Or download the signed, notarized `.dmg` from [Releases](https://github.com/momenbasel/puresnitch/releases/latest) and drag PureSnitch into `/Applications`. No Gatekeeper warnings, no quarantine workaround.

**PureSnitch has to live in `/Applications`.** macOS refuses to install background helpers for an app launched from the mounted disk image or from Downloads, so drag it across before opening it — PureSnitch will tell you if you forget.

On first launch it registers a privileged helper and opens the Network Monitor with a banner asking you to approve it in **System Settings → General → Login Items & Extensions → Allow in the Background**. Until that switch is on, macOS blocks the helper and the app can't see any traffic. The window picks up on its own once you flip it; no relaunch needed.

### Build from source

```bash
brew install xcodegen
git clone https://github.com/momenbasel/puresnitch.git
cd puresnitch
xcodegen generate
xcodebuild -project PureSnitch.xcodeproj -scheme PureSnitch -configuration Release \
  -derivedDataPath build \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO \
  build
open build/Build/Products/Release/PureSnitch.app
```

This certificate-free build launches the UI but cannot register the privileged
helper, so it does not provide live monitoring or enforcement. Use the signed
release, or configure your own Developer ID signing, to test helper-backed
features.

## Why this exists

Little Snitch is the gold standard for application firewalls on macOS, but it is commercial software. LuLu is free and excellent at the per-process kernel level, but the rules manager is spartan and there is no world map, no traffic graph, no built-in blocklist library. The macOS built-in firewall blocks inbound — it does nothing for outbound traffic.

So most Mac users sit between three choices: buy a commercial license, accept a barebones UI, or have no visibility into what their machine talks to at all.

PureSnitch is the fourth choice:

- **Same UI pattern as Little Snitch 6.** Menubar status item, world map, rules manager, connection alert popups. If you've used LS you already know how to use this.
- **Free under MIT.** Read the code, fork it, audit it. The matcher, the DNS proxy, the pf integration — all open.
- **No telemetry.** No analytics SDKs, crash reporters, or "anonymous usage" pings. Network access is limited to refreshing enabled blocklists at helper startup or on request, plus DNS messages explicitly sent to the optional local proxy.
- **Built like a Mac app, not a port.** Native SwiftUI for the windows, real `NSStatusItem` for the menubar, `SMAppService` for the privileged helper, XPC over a Mach service for the GUI ↔ daemon bridge.
- **Developer ID-signed + Apple-notarized.** No "developer cannot be verified" wall.

What PureSnitch is **honest** about: the shipping build does not have Apple's Network Extension entitlement, so it cannot perform per-process kernel filtering. It provides connection visibility and opt-in host-wide IP/CIDR/port rules through `pfctl`. Its DNS blocklist path is an experimental loopback proxy for clients you configure manually; PureSnitch does not change the macOS system resolver. LuLu has the required entitlement today and is the right choice if per-process filtering is a hard requirement.

## What it does

### Network Monitor
A live connection table with a per-process bandwidth sidebar and traffic summary. Sort, filter, and inspect the hosts seen for each process. The map UI is present, but v0.2.1 does not perform live IP geolocation or attach byte totals to individual connections.

### Rules Manager
A rules browser for All Rules, Active, Deny, Temporary, and Unapproved categories, plus Rule Groups and Blocklists in the sidebar. Existing rules can be searched, enabled, disabled, or deleted. In v0.2.1, persistent rule creation is available only from a DNS-proxy alert; the toolbar's general add/import/export controls are not implemented.

### Connection Alerts
The alert UI supports one-time Allow / Deny decisions or a permanent rule for the validated domain or IPv4 endpoint. In the shipping build it is used only for `ask` decisions made by the experimental DNS proxy. Passively observed app sockets are not paused; arbitrary per-process flow prompts require the non-shipping Network Extension build. Alert, Silent Allow, and Silent Deny control the proxy fallback policy.

### DNS over HTTPS
Experimental local DNS proxy with a built-in DoH client for Cloudflare, Quad9, Google, or a custom HTTPS endpoint. It binds to loopback and applies domain rules only to DNS requests sent to it manually. It does not intercept `getaddrinfo`, replace the macOS resolver, or change network-service DNS settings.

### Blocklist Library
1Hosts, OISD, StevenBlack, and HaGeZi are included. Enabled built-in lists refresh when the helper starts and when you request a refresh. v0.2.1 does not provide a UI or XPC API for adding custom blocklist URLs.

### Packet-Level Blocking
A runtime `com.apple/puresnitch` anchor in `pfctl` for deny rules targeting IPv4 addresses, CIDR ranges, and ports at the kernel. These rules are host-wide; per-process, domain, allow, and non-default-profile rules are not emitted to `pf`.

### Profiles
Default, Home, Public Wi-Fi, Lockdown. Only the Default profile is enforced in the shipping build; the others are stored organizational labels. Automatic SSID-based switching is not implemented.

### Menubar Status Item
Live up/down throughput, five-minute traffic graph, recent activity stream, denied-count badge, one-click mode picker.

## How it works

```
                    ┌─────────────────────────────────────┐
                    │            PureSnitch.app           │
                    │  ┌────────────────────────────────┐ │
                    │  │  SwiftUI GUI                   │ │
                    │  │  - Menubar status item         │ │
                    │  │  - Network Monitor window      │ │
                    │  │  - Rules Manager window        │ │
                    │  │  - Connection Alert popups     │ │
                    │  └──────────┬─────────────────────┘ │
                    │             │ XPC (Mach service)    │
                    │  ┌──────────▼─────────────────────┐ │
                    │  │  PureSnitchHelper (root daemon)│ │
                    │  │  - pfctl anchor manager        │ │
                    │  │  - DNS proxy (UDP/TCP :53)     │ │
                    │  │  - DoH upstream (Cloudflare)   │ │
                    │  │  - Blocklist fetch + parse     │ │
                    │  │  - nettop + lsof stream parser │ │
                    │  │  - SQLite rule store           │ │
                    │  └────────────────────────────────┘ │
                    └────────────────┬────────────────────┘
                                     │
                ┌────────────────────┼────────────────────┐
                │            macOS networking            │
                │   pfctl  ·  DNS  ·  bpf  ·  ess  ·  …  │
                └─────────────────────────────────────────┘
```

Three things move bytes:

1. **Optional DNS proxy** — An experimental loopback proxy answers requests from manually configured clients. Blocklisted domains return NXDOMAIN; everything else forwards over DoH. It is not installed as the system resolver.
2. **pfctl anchor** — A runtime `com.apple/puresnitch` sub-anchor carries validated, host-wide deny rules for IPv4 addresses, CIDR ranges, and ports. PureSnitch does not add declarations to `/etc/pf.conf`.
3. **Process and connection observability** — `nettop -P -L 0 -x -J bytes_in,bytes_out` is parsed continuously for process-level bandwidth. `lsof -i -n -P -F pcnPT` snapshots active connections every two seconds. Continuous observations update one session row, and retained history is capped at 5,000 rows. These are separate data sources; the release does not attribute byte totals or geolocation to individual connections.

## Anatomy of a rule

```
Rule(
    processBundleId: "com.example.app"   // optional
    processPath:     "/Applications/Example.app/…"
    remoteHost:      "*.tracker.com"     // glob
    remoteIP:        "1.2.3.0/24"        // CIDR
    remotePort:      443
    direction:       outgoing | incoming | any
    action:          allow | deny | ask
    scope:           process | domain | ip | port | any
    priority:        100
    profile:         "default"
    temporary:       false
    expiresAt:       Date?
)
```

The matcher walks enabled rules in `priority` order (DESC) and applies the first match. No match → fall back to the active mode (`alert`, `silentAllow`, `silentDeny`). In the shipping build, the DNS proxy evaluates Default-profile domain rules. The `pf` backend emits only Default-profile, host-wide deny rules; an IPv6 alert decision is one-time because the persistent `pf` backend is IPv4-only.

## Permissions

PureSnitch needs to install a small **privileged helper** at first launch in order to:

- read per-process connection state via `nettop` and `lsof`
- and, only if an authorized local administrator turns on **Enforcement** in Settings: load a validated `com.apple/puresnitch` runtime sub-anchor and start the experimental loopback DNS proxy

Enforcement is **off by default**. Out of the box PureSnitch watches traffic. Enabling it loads the PureSnitch `pf` anchor and starts the optional DNS proxy; it does not change the macOS resolver.

The helper is installed via `SMAppService.daemon`, the modern replacement for `SMJobBless`. macOS will surface it in **System Settings → General → Login Items & Extensions** as a service you can enable, disable or remove with a single switch. PureSnitch never asks for your password during normal operation; the helper handles privileged calls on its own through XPC.

The first active console administrator to connect becomes the owner of the
system-wide helper. Subsequent XPC requests must come from that same account
while it remains an administrator and, in release builds, from the Developer
ID-signed PureSnitch app. Rules, settings, and connection history are stored
root-only.

What PureSnitch does **not** do:

- It does not collect telemetry, crash reports, or usage analytics.
- It does not require an account, license check, or any kind of identity.
- It does not perform live IP-geolocation requests. The current release does not send addresses to an external geolocation service.
- It does not modify macOS DNS settings. Firewall rules are loaded only after you turn on Enforcement in Settings.

## Screenshots

| Network Monitor | Rules Manager |
|---|---|
| ![Network Monitor](docs/screenshot-monitor.png) | ![Rules Manager](docs/screenshot-rules.png) |

## Comparison

| | PureSnitch | Little Snitch | LuLu | macOS Firewall |
|---|---|---|---|---|
| License | **MIT, open source** | Commercial | GPL, open source | Apple, closed |
| Price | **Free** | Paid | Free | Bundled |
| Traffic graph / map UI | ✅ (no live geo) | ✅ | ❌ | ❌ |
| Rules browser (toggle/delete; alert-created rules) | ✅ | ✅ | basic | ❌ |
| DNS proxy + DoH | experimental, manual | ✅ | ❌ | ❌ |
| Domain blocklists out of the box | ✅ (1Hosts, OISD, StevenBlack, HaGeZi) | ✅ | ❌ | ❌ |
| pf-based IP/CIDR blocking | ✅ | ✅ | n/a | basic |
| Per-process kernel filtering | gated (NE entitlement) | ✅ | ✅ | ❌ |
| Host-wide IP/CIDR/port blocking | ✅ (`pf`) | ✅ | ✅ | basic |
| Telemetry | none | none | none | n/a |
| Auditable source | yes | no | yes | no |

If per-process kernel filtering matters to you today, use **LuLu** — it's free, open source and has the Network Extension entitlement. If you want the Little Snitch UI without buying a commercial license, that is what PureSnitch is for.

## Roadmap

- [x] **v0.1.0** — Initial signed and notarized arm64 release.
- [x] **v0.2.0** — Universal macOS 13+ monitor build, rules UI, blocklists, and opt-in `pf` enforcement.
- [x] **v0.2.1** — DNS/PF safety hardening and release reliability fixes.
- [ ] **Future** — Ship the `NEFilterDataProvider` path after Apple grants the required entitlement and provisioning profiles.
- [ ] **v0.3.0** — Internet Access Policy (`.lsiap`) file support, on par with Little Snitch's IAP feature. Other firewalls can read the same file.
- [ ] **v0.4.0** — iCloud sync of rule sets between Macs.
- [ ] **v0.5.0** — Endpoint Security Framework integration for process-event awareness.

## FAQ

**Is this a Little Snitch clone?** It is an independent open-source alternative with a deliberately similar user interface. The blocking engine, the DNS proxy, the matcher — all written from scratch. No Little Snitch source, assets or proprietary plist formats are used. "Little Snitch" is a registered trademark of Objective Development Software GmbH; this project is not affiliated with or endorsed by Objective Development.

**Does PureSnitch send my traffic anywhere?** PureSnitch has no telemetry, analytics, or phone-home service. It fetches enabled blocklists when the helper starts and when you request a refresh. DNS messages reach a DoH upstream only when a client has been manually configured to use the experimental local proxy. The current release does not perform live IP-geolocation requests.

**Why isn't per-process blocking at parity with Little Snitch?** Per-process blocking requires Apple's Network Extension entitlement and matching provisioning profiles. The hook points exist under `Sources/NetExt/`, but they are not in the shipping build. Current `pf` rules are host-wide, and DNS rules apply only to clients manually pointed at the experimental proxy.

**Will this run on Intel Macs?** Yes. From v0.2.0 the release DMG is a universal binary (`arm64` + `x86_64`) with a macOS 13 (Ventura) minimum. v0.1.0 was arm64-only and would not launch on Intel at all.

**How is it different from LuLu?** [LuLu](https://github.com/objective-see/LuLu) is excellent and has had the Network Extension entitlement for years. PureSnitch focuses on a Little Snitch-style monitor UI, traffic graph, mode picker, optional manual DoH proxy, blocklist library, and a written-from-scratch rule engine. Try both; use whichever fits.

**Does it work alongside Pi-hole / AdGuard Home / NextDNS?** The experimental proxy accepts a custom DoH upstream, but you must configure each client to use the loopback proxy yourself. PureSnitch does not alter system DNS or automatically layer itself over another resolver.

**What about Tailscale, WireGuard, ProtonVPN?** PureSnitch's `pf` anchor is host-wide and can interact with VPN routing or other `pf` rules. Test rules with your VPN before relying on them. The optional DNS proxy stays on loopback and PureSnitch does not replace VPN-provided DNS.

## Project structure

```
puresnitch/
├── Sources/
│   ├── GUI/          # SwiftUI app (menubar, windows, alerts)
│   ├── Helper/       # Privileged daemon (pfctl, DNS proxy, nettop)
│   ├── NetExt/       # Network System Extension (dormant; needs Apple entitlement)
│   └── Shared/       # Rule model, SQLite store, XPC protocol, matcher
├── Resources/
│   └── Assets.xcassets/AppIcon.appiconset/
├── Scripts/
│   ├── make_icon.sh        # Generates app icon from Swift CoreGraphics
│   ├── sign_and_notarize.sh
│   └── make_dmg.sh
├── docs/                   # Screenshots, architecture, translations
├── .github/workflows/      # CI
├── project.yml             # XcodeGen project definition
├── README.md
└── LICENSE                 # MIT
```

## Security

- The privileged helper is installed via `SMAppService.daemon`, the modern replacement for `SMJobBless`. Trust boundary is the system Login Items & Extensions list.
- The XPC interface is typed; the helper validates every request shape and refuses anything outside the declared protocol.
- Enforcement uses the active macOS `com.apple/*` parent anchor, writes a root-only generated anchor under `/Library/Application Support/PureSnitch`, and does not add declarations to or reload `/etc/pf.conf`.
- The `pf` backend emits deny-only, Default-profile, host-wide IPv4/CIDR/port rules. It never emits per-process, domain, allow, or IPv6 rules.
- Releases before v0.2.1 may have left `/etc/pf.conf.puresnitch.bak` as a recovery artifact. v0.2.1 removes only the two exact legacy declarations and deliberately does not delete that backup.
- The release helper accepts XPC only from the signed app and its persisted local administrator owner; the root database, WAL, and shared-memory files are mode `0600` inside a `0700` directory.
- The experimental DNS proxy binds to loopback and does not reconfigure the system resolver.
- All destructive operations (purge rules, reset blocklists) require explicit confirmation by default.

If you find a security issue, please open a private security advisory rather than a public issue.

## Contributing

Pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

Especially welcome:
- `NEFilterDataProvider` wiring for the dormant `Sources/NetExt/` provider, if you have access to Apple's Network Extension entitlement
- Internet Access Policy (`.lsiap`) parser and integration
- Translations beyond English
- Additional blocklist providers
- XCTest coverage for the rule matcher and DNS proxy

## Acknowledgments

- [@objective-see](https://github.com/objective-see) for [LuLu](https://github.com/objective-see/LuLu), the reference free firewall for macOS
- [Objective Development](https://www.obdev.at/) for shaping what an outbound firewall UI should feel like with Little Snitch
- [1Hosts](https://github.com/badmojr/1Hosts), [OISD](https://oisd.nl/), [StevenBlack](https://github.com/StevenBlack/hosts) and [HaGeZi](https://github.com/hagezi/dns-blocklists) for the blocklist work everyone in this space stands on top of
- Cloudflare, Quad9 and Google for free public DoH resolvers

## License

MIT. See [LICENSE](LICENSE). Use it, fork it, ship it under your own name if you want — the only thing the license asks is that the notice stays.
