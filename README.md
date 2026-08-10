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
  <img src="https://img.shields.io/badge/Swift-5.10-orange?style=flat-square" alt="Swift 5.10">
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
brew tap momenbasel/puresnitch
brew install --cask puresnitch
```

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
  -derivedDataPath build build
open build/Build/Products/Release/PureSnitch.app
```

## Why this exists

Little Snitch is the gold standard for application firewalls on macOS. It costs $59 per machine. LuLu is free and excellent at the per-process kernel level, but the rules manager is spartan and there is no world map, no traffic graph, no built-in blocklist library. The macOS built-in firewall blocks inbound — it does nothing for outbound traffic.

So most Mac users sit between three choices: pay $59, accept a barebones UI, or have no visibility into what their machine talks to at all.

PureSnitch is the fourth choice:

- **Same UI pattern as Little Snitch 6.** Menubar status item, world map, rules manager, connection alert popups. If you've used LS you already know how to use this.
- **Free under MIT.** Read the code, fork it, audit it. The matcher, the DNS proxy, the pf integration — all open.
- **No telemetry.** No analytics SDKs. No crash reporters phoning home. No "anonymous usage" pings. The only outbound traffic from PureSnitch itself is your DNS queries going to the DoH resolver you chose, and (toggle-able) ip-api.com for the world map.
- **Built like a Mac app, not a port.** Native SwiftUI for the windows, real `NSStatusItem` for the menubar, `SMAppService` for the privileged helper, XPC over a Mach service for the GUI ↔ daemon bridge.
- **Signed + notarized by Apple.** No "developer cannot be verified" wall.

What PureSnitch is **honest** about: per-process kernel filtering is the one feature gated behind Apple's `com.apple.developer.networking.networkextension` entitlement. The hook points exist in `Sources/NetExt/` dormant in the codebase. Until Apple grants the entitlement, PureSnitch blocks at DNS level and packet level (`pfctl`), which in practice catches everything that resolves a hostname — i.e. nearly everything that is not hardcoded-IP malware. LuLu has the entitlement today and is the right choice if per-process kernel filtering is a hard requirement for you right now.

## What it does

### Network Monitor
A live world map of every active connection your Mac is making, with a per-process bandwidth sidebar and a summary pane that ranks the top processes, domains and countries by traffic volume. Sort, filter and click into any process to see exactly which hosts it talked to in the last five minutes.

### Rules Manager
The full rules UI you'd expect from a Little Snitch-style firewall — All Rules, Active, Deny, Temporary, Unapproved categories, Rule Groups, Blocklists in the sidebar. Each rule shows process, allow/deny chip, priority, hit count. Search across every field. Glob hostnames, CIDR ranges, port-specific rules, time-bounded rules with expiry.

### Connection Alerts
Default-deny mode pops a clean alert on every new outbound connection: "Allow / Deny", "remember this", scope (this process / this domain / this IP / this port), duration (5 min / 1 hr / forever). Three modes total — Alert, Silent Allow, Silent Deny — switchable from the menubar.

### DNS over HTTPS
Built-in DoH client to Cloudflare, Quad9, Google, or any DoH endpoint you point it at. Domain-level blocking runs through a local DNS proxy on `127.0.0.1:53`, so every `getaddrinfo` your apps make passes through PureSnitch before leaving the machine.

### Blocklist Library
1Hosts, OISD, StevenBlack, HaGeZi out of the box. Subscribe, refresh on a schedule, audit which entries are matching. Bring your own list URLs too.

### Packet-Level Blocking
A `puresnitch` anchor in `pfctl` for IP, CIDR and port blocking at the kernel — works regardless of which process initiated the connection.

### Profiles
Default, Home, Public Wi-Fi, Lockdown. Different rule sets active on different networks. Switches automatically when the SSID changes.

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

1. **DNS interception** — A local DNS proxy on `127.0.0.1:53` answers every query. Blocklisted domains return NXDOMAIN; everything else forwards over DoH to the resolver of your choice.
2. **pfctl anchor** — A `puresnitch` anchor in `/etc/pf.conf` carries block-rules for IPs, CIDR ranges and ports. Kernel-level.
3. **Process and connection observability** — `nettop -P -L 0 -x -J bytes_in,bytes_out` is parsed continuously for per-process bandwidth. `lsof -i -n -P -F pcnT` snapshots active connections every two seconds. Both feed the GUI's process list, world map and traffic graph.

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

The matcher walks enabled rules in `priority` order (DESC) and applies the first match. No match → fall back to the active mode (`alert`, `silentAllow`, `silentDeny`).

## Permissions

PureSnitch needs to install a small **privileged helper** at first launch in order to:

- read per-process connection state via `nettop` and `lsof`
- and, only if you turn on **Enforcement** in Settings: write `pfctl` rules to `/etc/pf.anchors/puresnitch` and bind `127.0.0.1:53` for the local DNS proxy

Enforcement is **off by default**. Out of the box PureSnitch watches; it does not touch your firewall or your resolver until you ask it to.

The helper is installed via `SMAppService.daemon`, the modern replacement for `SMJobBless`. macOS will surface it in **System Settings → General → Login Items & Extensions** as a service you can enable, disable or remove with a single switch. PureSnitch never asks for your password during normal operation; the helper handles privileged calls on its own through XPC.

What PureSnitch does **not** do:

- It does not collect telemetry, crash reports, or usage analytics.
- It does not require an account, license check, or any kind of identity.
- It does not move data anywhere except the DoH resolver you pick and (optionally, toggle-able) ip-api.com for the world map.
- It does not modify your firewall or DNS settings until you turn on Enforcement in Settings.

## Screenshots

| Network Monitor | Rules Manager |
|---|---|
| ![Network Monitor](docs/screenshot-monitor.png) | ![Rules Manager](docs/screenshot-rules.png) |

## Comparison

| | PureSnitch | Little Snitch | LuLu | macOS Firewall |
|---|---|---|---|---|
| License | **MIT, open source** | Commercial, $59 | GPL, open source | Apple, closed |
| Price | **Free** | $59 / Mac | Free | Bundled |
| World map / traffic graph | ✅ | ✅ | ❌ | ❌ |
| Rules manager (LS-style) | ✅ | ✅ | basic | ❌ |
| DNS proxy + DoH | ✅ | ✅ | ❌ | ❌ |
| Domain blocklists out of the box | ✅ (1Hosts, OISD, StevenBlack, HaGeZi) | ✅ | ❌ | ❌ |
| pf-based IP/CIDR blocking | ✅ | ✅ | n/a | basic |
| Per-process kernel filtering | gated (NE entitlement) | ✅ | ✅ | ❌ |
| Outbound blocking | ✅ | ✅ | ✅ | ❌ |
| Inbound blocking | ✅ | ✅ | ✅ | ✅ |
| Telemetry | none | none | none | n/a |
| Auditable source | yes | no | yes | no |

If per-process kernel filtering matters to you today, use **LuLu** — it's free, open source and has the Network Extension entitlement. If you want the Little Snitch UI without paying $59, that is what PureSnitch is for.

## Roadmap

- [x] **v0.1.0** — Signed + notarized release. DNS-level + pfctl-level firewall. Full Little Snitch-style UI.
- [ ] **v0.2.0** — System Extension path (`NEFilterDataProvider`) for per-process kernel filtering. Requires Apple's `com.apple.developer.networking.networkextension` entitlement.
- [ ] **v0.3.0** — Internet Access Policy (`.lsiap`) file support, on par with Little Snitch's IAP feature. Other firewalls can read the same file.
- [ ] **v0.4.0** — iCloud sync of rule sets between Macs.
- [ ] **v0.5.0** — Endpoint Security Framework integration for process-event awareness.

## FAQ

**Is this a Little Snitch clone?** It is an independent open-source alternative with a deliberately similar user interface. The blocking engine, the DNS proxy, the matcher — all written from scratch. No Little Snitch source, assets or proprietary plist formats are used. "Little Snitch" is a registered trademark of Objective Development Software GmbH; this project is not affiliated with or endorsed by Objective Development.

**Does PureSnitch send my traffic anywhere?** No. Your DNS queries leave only as far as the DoH upstream you pick (Cloudflare by default — override in Settings). PureSnitch itself has no telemetry, no analytics, no phone-home. IP→country lookups go to ip-api.com (free tier) and can be disabled.

**Why isn't per-process blocking at parity with Little Snitch?** Per-process blocking requires Apple's Network Extension entitlement, which is application-gated. The hook points exist in this codebase under `Sources/NetExt/`. The entitlement must be granted by Apple. Until then, blocking happens at DNS-level and packet-level (pfctl), which catches the overwhelming majority of unwanted traffic in practice — anything that resolves a hostname.

**Will this run on Intel Macs?** Yes. From v0.2.0 the release DMG is a universal binary (`arm64` + `x86_64`) with a macOS 13 (Ventura) minimum. v0.1.0 was arm64-only and would not launch on Intel at all.

**How is it different from LuLu?** [LuLu](https://github.com/objective-see/LuLu) is excellent and has had the Network Extension entitlement for years. PureSnitch differs in: a Little Snitch-style UI (world map, traffic graph, mode picker), DoH out-of-the-box, an opinionated blocklist library, and a written-from-scratch rule engine. Try both; use whichever fits.

**Does it work alongside Pi-hole / AdGuard Home / NextDNS?** Yes. Point PureSnitch's DoH upstream at your own DoH endpoint and PureSnitch becomes a per-device enforcement layer on top of your network-wide blocker.

**What about Tailscale, WireGuard, ProtonVPN?** PureSnitch's pfctl rules apply at kernel level, so they work alongside VPN tunnels on `utun*` interfaces. The DNS proxy on `127.0.0.1:53` is intentionally a loopback bind, so it stays out of the way of VPN-pushed DNS unless you opt in via the "use PureSnitch as system DNS" toggle.

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
- pfctl writes are scoped to a single anchor (`puresnitch`) so the rest of `/etc/pf.conf` is never touched.
- The DNS proxy refuses queries from anything that isn't local loopback.
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
