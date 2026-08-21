# Architecture

## Process model

The shipping PureSnitch build uses two processes: the GUI and its privileged
helper. The optional Network System Extension is a separate, non-shipping build
flavour that requires Apple-issued provisioning profiles.

```
┌──────────────────────────────────────────────────────────────────────┐
│                          PureSnitch.app                              │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                       PureSnitch (GUI)                         │  │
│  │  user-space, runs as the logged-in user                        │  │
│  │  Bundle: io.moamenbasel.puresnitch                             │  │
│  │  - SwiftUI views (Menubar, NetworkMonitor, RulesManager, ...)  │  │
│  │  - HelperClient (NSXPCConnection over a Mach service)          │  │
│  │  - AppState (Observable, drives all views)                     │  │
│  └────────────────────────────┬───────────────────────────────────┘  │
│                               │ XPC                                  │
│  ┌────────────────────────────▼───────────────────────────────────┐  │
│  │                  PureSnitchHelper (daemon)                     │  │
│  │  root, registered with launchd via SMAppService.daemon         │  │
│  │  Bundle: io.moamenbasel.puresnitch.helper                      │  │
│  │  - PFManager     (root-only runtime anchor + pfctl)            │  │
│  │  - DNSProxy      (NWListener on UDP/TCP 53 + DoH upstream)     │  │
│  │  - NetMonitor    (parses nettop + lsof streams)                │  │
│  │  - BlocklistManager (fetches HOSTS-format lists, parses)       │  │
│  │  - RuleStore     (SQLite at /Library/Application Support/…)    │  │
│  │  - HelperService (NSXPCListenerDelegate)                       │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
                               │
            ┌──────────────────┼────────────────────┐
            │           macOS kernel + tools         │
            │  pfctl(8)  ·  nettop(1)  ·  lsof(8)    │
            │  Network.framework  ·  dispatch  ·  …  │
            └────────────────────────────────────────┘
```

## XPC contract

Defined in `Sources/Shared/HelperProtocol.swift`:

- **HelperProtocol** — GUI → Helper. Methods: `getStatus`, `setMode`, `addRule`, `removeRule`, `listRules`, `startMonitoring`, `installPF`, `refreshBlocklists`, `setDoHUpstream`, etc.
- **HelperClientProtocol** — Helper → GUI. Methods: `notifyConnection`, `notifyTraffic`, `notifyAlert(connectionJSON, reply)`, `notifyLog`.

`notifyAlert` is currently used when the experimental DNS proxy evaluates an
`ask` rule. The GUI's `AppState.presentAlert(...)` puts up a SwiftUI sheet and
returns the Allow/Deny choice through the reply block. Passive connections found
by `lsof` are reported with `notifyConnection`; the shipping build does not
pause those sockets.

The helper accepts the first active console administrator as the owner of its
system-wide state. Every request is re-authorized against that owner and the
current administrator membership; release builds additionally require the
Developer ID-signed PureSnitch client. Desired enforcement and mode are stored
by the root helper and are authoritative after GUI or helper restarts. The
SQLite database, policy metadata, and PF state files are root-only.

## Experimental DNS path

```
manually configured client → loopback:53 (PureSnitch DNS proxy)
                                      │
                                      ├─ blocklist match? ──→ NXDOMAIN
                                      │
                                      ├─ rule says deny?  ──→ NXDOMAIN
                                      │
                                      ├─ rule says ask?   ──→ notifyAlert
                                      │                       │
                                      │                       ├─ allow ─→ DoH forward
                                      │                       └─ deny  ─→ NXDOMAIN
                                      │
                                      └─ default              ──→ DoH forward
```

Both UDP and TCP DNS are handled on loopback. DoH is an
`application/dns-message` POST to a single configurable HTTPS upstream.
PureSnitch does not intercept `libsystem_resolver`, modify network-service DNS
settings, or install the proxy as the macOS system resolver.

## pfctl path

When enforcement is enabled, PureSnitch first verifies that the active macOS
ruleset exposes the standard `com.apple/*` parent anchor. It then obtains its
own `pfctl -E` reference and loads the runtime sub-anchor
`com.apple/puresnitch`. The generated file is root-only at
`/Library/Application Support/PureSnitch/pf-anchor.conf`; PureSnitch does not
add declarations to or reload `/etc/pf.conf`.

The anchor file is rewritten by the helper from the enforceable subset of
`Rule[]` whenever rules change. Only enabled, unexpired, Default-profile,
host-wide deny rules are emitted. IP/CIDR rules are IPv4-only; domain,
per-process, allow, and non-default-profile rules are deliberately excluded:

```
block out quick proto { tcp udp } to 198.51.100.0/24
block in quick proto { tcp udp } from 203.0.113.7
block out quick proto { tcp udp } to any port 443
```

The helper stores only its own enable-reference token, releases it with
`pfctl -X`, and never disables global `pf`. Cleanup flushes only
`com.apple/puresnitch`. An exact legacy migration removes the two declarations
used by releases before v0.2.1 only after validating the candidate main ruleset.
The pre-migration `/etc/pf.conf.puresnitch.bak` is retained for manual recovery.

## Per-process observation

- `nettop -P -L 0 -x -J bytes_in,bytes_out -s 1` runs continuously. Each line update is parsed for process-level throughput which feeds the menubar histogram and Network Monitor process list.
- `lsof -i -n -P -F pcnPT` is polled every 2 s. Output is parsed into `Connection` records with PID, process path, transport, local/remote IP+port, and an inferred bundle ID (via Info.plist of the enclosing `.app`). A continuously observed socket keeps one database row; a gap starts a new session, and history is capped at the newest 5,000 rows. These snapshots do not carry per-connection byte totals, and v0.2.1 does not perform live IP geolocation.

## Rule matching

`RuleMatcher.decision(for:rules:defaultMode:)` walks enabled, unexpired rules in `priority DESC` order. First match wins. No match = fall back to active mode (`alert` → `.ask`, `silentAllow` → `.allow`, `silentDeny` → `.deny`).

Host glob: `*.example.com`, `.example.com` both match.
IP CIDR: `10.0.0.0/8` matches anywhere in that block.
Process: bundle ID match wins; otherwise path prefix.

## NetExt — per-process firewall (Network System Extension)

`Sources/NetExt/FilterDataProvider.swift` is a `NEFilterDataProvider` content filter. It is built and embedded only by `project-netext.yml`; the shipping `project.yml` deliberately excludes it. With the required Apple-issued profiles, it provides per-process filtering using the same macOS mechanism as Little Snitch.

- `handleNewFlow` evaluates each socket flow with the shared `RuleMatcher`; allow → `.allow()`, deny → `.drop()`, ask → `.pause()` then resume with the user's verdict.
- App ↔ extension XPC: `Shared/IPCConnection.swift` (extension vends a mach service named by `NEMachServiceName`; the app connects and receives prompts, reusing the connection-alert UI).
- Rules reach the sandboxed extension via the app-group container (`Shared/SharedRuleBridge.swift`), mirrored by the GUI on every rule/mode change.
- Activation: `GUI/App/SystemExtensionManager.swift` (`OSSystemExtensionRequest` + `NEFilterManager`).

Shipping this separate flavour requires the `content-filter-provider-systemextension` entitlement, matching Developer ID provisioning profiles, signing + notarization, and the app installed in `/Applications`. See `Sources/NetExt/README.md`. The helper remains responsible for rule storage, `pf` rules, and the optional manual DNS proxy.
