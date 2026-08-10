import SwiftUI
import AppKit

@main
struct PureSnitchApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate

    var body: some Scene {
        Settings {
            SettingsView()
                .environmentObject(delegate.state)
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let state = AppState()
    var menubar: MenubarController!
    var windowManager: WindowManager!
    var systemExtension: SystemExtensionManager!

    nonisolated override init() { super.init() }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        windowManager = WindowManager(state: state)
        menubar = MenubarController(state: state, windows: windowManager)
        menubar.install()
        state.helper.registerDaemon()
        // bootstrap() (rule load + monitoring) is driven by HelperClient once
        // the helper is actually reachable — see HelperClient.setConnected.
        state.helper.connect()
        // Seed the app-group snapshot so the network extension has rules to read.
        state.syncSharedRules()

        // Per-process firewall (Network System Extension). `activate()` is a
        // no-op unless this build embeds one — the monitor-only release does
        // not, so no extension approval prompt appears.
        systemExtension = SystemExtensionManager(state: state)
        if ProcessInfo.processInfo.environment["PURESNITCH_DEMO"] != "1" {
            systemExtension.activate()
        }

        // A menu-bar-only app that shows nothing on first launch reads as
        // broken. Open the monitor once so the helper-approval banner is
        // actually seen.
        if ProcessInfo.processInfo.environment["PURESNITCH_DEMO"] != "1",
           !UserDefaults.standard.bool(forKey: "PSDidFirstRun") {
            UserDefaults.standard.set(true, forKey: "PSDidFirstRun")
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.windowManager.showNetworkMonitor()
            }
        }

        if ProcessInfo.processInfo.environment["PURESNITCH_DEMO"] == "1" {
            seedDemoState()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) {
                if ProcessInfo.processInfo.environment["PURESNITCH_DEMO_WINDOW"] == "monitor" {
                    self.windowManager.showNetworkMonitor()
                } else if ProcessInfo.processInfo.environment["PURESNITCH_DEMO_WINDOW"] == "rules" {
                    self.windowManager.showRulesManager()
                } else if ProcessInfo.processInfo.environment["PURESNITCH_DEMO_WINDOW"] == "settings" {
                    self.windowManager.showSettings()
                }
            }
        }
    }

    private func seedDemoState() {
        // Synthetic samples for the menubar + popover traffic graph
        var samples: [TrafficSample] = []
        let now = Date()
        for i in 0..<60 {
            let t = now.addingTimeInterval(TimeInterval(i - 60))
            let inB = Int64.random(in: 50_000...450_000)
            let outB = Int64.random(in: 20_000...250_000)
            samples.append(TrafficSample(timestamp: t, bytesIn: inB, bytesOut: outB))
        }
        state.trafficHistory = samples
        state.currentIn = 332_000
        state.currentOut = 2_180_000
        state.totalIn = 952_000_000
        state.totalOut = 288_000_000
        state.deniedCount = 3
        state.incomingCount = 19
        state.unconfirmedCount = 283

        // Synthetic process list
        let procs: [(String, Int64, Int64, String)] = [
            ("Dia", 3_580_000_000, 480_000_000, "compass"),
            ("iTerm", 5_200_000_000, 410_000_000, "terminal"),
            ("Discord", 768_000_000, 95_000_000, "message"),
            ("claude", 322_000_000, 18_000_000, "sparkles"),
            ("Slack", 285_000_000, 26_000_000, "bubble.left.and.bubble.right"),
            ("WhatsApp", 80_000_000, 30_000_000, "bubble.left"),
            ("Telegram", 78_000_000, 14_000_000, "paperplane"),
            ("Spotify", 58_000_000, 4_500_000, "music.note"),
            ("Visual Studio Code", 51_500_000, 6_700_000, "chevron.left.forwardslash.chevron.right"),
            ("Cursor", 28_300_000, 1_500_000, "command"),
            ("Arc", 22_400_000, 5_800_000, "globe"),
            ("Microsoft Edge", 17_200_000, 3_400_000, "globe.americas"),
            ("Google Chrome", 14_900_000, 2_800_000, "globe.europe.africa"),
            ("MacUpdater", 8_300_000, 920_000, "arrow.clockwise"),
            ("Setapp", 6_500_000, 870_000, "rectangle.grid.2x2"),
            ("bun", 5_200_000, 1_400_000, "hare.fill"),
            ("Microsoft Teams", 4_100_000, 1_200_000, "person.3"),
            ("ChatGPT", 2_100_000, 400_000, "brain")
        ]
        state.topProcesses = procs.map { (n, i, o, _) in
            AppState.ProcessStats(id: n, name: n, bytesIn: i, bytesOut: o, icon: AppIcon.resolve(name: n))
        }

        let domains: [(String, Int64)] = [
            ("fbcdn.net", 12_300_000_000),
            ("googlevideo.com", 7_080_000_000),
            ("scdn.co", 7_080_000_000),
            ("apple.com", 1_240_000_000),
            ("github.com", 482_000_000)
        ]
        state.topDomains = domains.map { (d, t) in
            AppState.DomainStats(id: d, domain: d, bytesIn: t * 7 / 10, bytesOut: t * 3 / 10)
        }

        let countries: [(String, String, Int64)] = [
            ("Canada", "CA", 28_300_000_000),
            ("United States", "US", 23_200_000_000),
            ("Germany", "DE", 14_200_000_000),
            ("United Kingdom", "GB", 4_100_000_000),
            ("Japan", "JP", 1_900_000_000)
        ]
        state.topCountries = countries.map { (n, c, t) in
            AppState.CountryStats(id: c, country: n, countryCode: c, bytesIn: t * 6 / 10, bytesOut: t * 4 / 10)
        }

        // Synthetic rules so the demo showcases the populated Rules manager
        state.rules = [
            Rule(processBundleId: "com.spotify.client", processPath: "/Applications/Spotify.app", processName: "Spotify", remoteHost: "*.scdn.co", direction: .outgoing, action: .allow, scope: .domain, priority: 100, profile: "default", notes: "Allow audio streaming", lastUsedAt: now.addingTimeInterval(-120), hitCount: 482),
            Rule(processBundleId: "com.microsoft.VSCode", processPath: "/Applications/Visual Studio Code.app", processName: "Visual Studio Code", remoteHost: "update.code.visualstudio.com", direction: .outgoing, action: .allow, scope: .domain, priority: 90, profile: "default", lastUsedAt: now.addingTimeInterval(-3600), hitCount: 31),
            Rule(processBundleId: "com.google.Chrome", processPath: "/Applications/Google Chrome.app", processName: "Google Chrome", remoteHost: "*.googleapis.com", direction: .outgoing, action: .allow, scope: .domain, priority: 80, profile: "default", hitCount: 1290),
            Rule(processBundleId: "com.hnc.Discord", processPath: "/Applications/Discord.app", processName: "Discord", remoteHost: "*.discord.gg", direction: .outgoing, action: .allow, scope: .domain, priority: 70, profile: "default", hitCount: 96),
            Rule(processBundleId: "com.adobe.acc", processPath: "/Applications/Adobe Creative Cloud.app", processName: "Adobe CC", remoteHost: "*.adobe.io", direction: .outgoing, action: .deny, scope: .domain, priority: 95, profile: "default", notes: "Block telemetry", hitCount: 211),
            Rule(processName: "Any Process", remoteHost: "*.doubleclick.net", direction: .outgoing, action: .deny, scope: .domain, priority: 60, profile: "default", notes: "Ad/tracker", hitCount: 3771),
            Rule(processName: "Any Process", remoteHost: "*.facebook.com", direction: .outgoing, action: .deny, scope: .domain, priority: 60, profile: "default", notes: "Tracker", hitCount: 845),
            Rule(processBundleId: "us.zoom.xos", processPath: "/Applications/Zoom.app", processName: "zoom.us", remoteHost: "*.zoom.us", direction: .outgoing, action: .allow, scope: .domain, priority: 50, profile: "default", temporary: true, expiresAt: now.addingTimeInterval(3600), hitCount: 12),
            Rule(processBundleId: "ru.keepcoder.Telegram", processPath: "/Applications/Telegram.app", processName: "Telegram", remoteHost: "149.154.167.0/24", remoteIP: "149.154.167.0/24", direction: .outgoing, action: .ask, scope: .ip, priority: 40, profile: "default", hitCount: 0)
        ]

        // Synthetic blocklists
        state.blocklists = [
            BlocklistInfo(name: "FireHOL", url: "", enabled: true, entryCount: 3768),
            BlocklistInfo(name: "NoCoin", url: "", enabled: true, entryCount: 313),
            BlocklistInfo(name: "URLhaus", url: "", enabled: true, entryCount: 513),
            BlocklistInfo(name: "Anti PopAds", url: "", enabled: true, entryCount: 755),
            BlocklistInfo(name: "Peter Lowe", url: "", enabled: true, entryCount: 3509),
            BlocklistInfo(name: "Ad Way", url: "", enabled: true, entryCount: 6540),
            BlocklistInfo(name: "Anudeep", url: "", enabled: true, entryCount: 42258),
            BlocklistInfo(name: "KADhosts", url: "", enabled: true, entryCount: 48346),
            BlocklistInfo(name: "OISD", url: "", enabled: true, entryCount: 57167),
            BlocklistInfo(name: "HaGeZi Multi Light", url: "", enabled: true, entryCount: 60913),
            BlocklistInfo(name: "1Host Lite", url: "", enabled: true, entryCount: 94647),
            BlocklistInfo(name: "HaGeZi Threat", url: "", enabled: true, entryCount: 301675)
        ]
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        windowManager.showNetworkMonitor()
        return true
    }
}
