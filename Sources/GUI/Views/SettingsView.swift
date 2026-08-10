import SwiftUI
import ServiceManagement

struct SettingsView: View {
    @EnvironmentObject var state: AppState
    @State private var doh = AppConstants.defaultDoHUpstream
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled

    var body: some View {
        TabView {
            generalTab.tabItem { Label("General", systemImage: "gear") }
            dnsTab.tabItem { Label("DNS", systemImage: "globe") }
            blocklistsTab.tabItem { Label("Blocklists", systemImage: "shield.lefthalf.filled") }
            profilesTab.tabItem { Label("Profiles", systemImage: "person.crop.circle") }
            aboutTab.tabItem { Label("About", systemImage: "info.circle") }
        }
        .padding(16)
        .frame(width: 520, height: 420)
    }

    private var generalTab: some View {
        VStack(alignment: .leading, spacing: 0) {
            HelperBanner()
            Form {
                Section("Privileged helper") {
                    HStack {
                        Text(helperSummary)
                        Spacer()
                        Button("Check Again") { state.helper.refreshInstallState(); state.helper.ping() }
                    }
                    if state.helperInstallState != .enabled {
                        Button("Open Login Items…") { state.helper.openLoginItemsSettings() }
                    }
                }
                Section("Menu bar") {
                    Toggle("Show download and upload speeds in the menu bar",
                           isOn: $state.showSpeedsInMenuBar)
                }
                Section("General") {
                    Toggle("Launch PureSnitch at login", isOn: $launchAtLogin)
                        .onChange(of: launchAtLogin) { newValue in setLaunchAtLogin(newValue) }
                    Toggle("Show alerts on all Spaces", isOn: $state.showAlertsOnAllSpaces)
                }
                Section("Enforcement") {
                    Toggle("Block traffic, don't just watch it", isOn: $state.enforcementEnabled)
                        .disabled(!state.helperConnected)
                    Text("Off by default. Turning this on lets PureSnitch load a pf firewall anchor and run a DNS proxy on port \(AppConstants.dnsProxyPort), which changes how this Mac resolves names and filters packets. Leave it off to use PureSnitch purely as a traffic monitor.")
                        .font(.caption).foregroundColor(.secondary)
                }
                Section("Mode") {
                    Picker("Default mode", selection: Binding(get: { state.mode }, set: { state.setMode($0) })) {
                        Text("Alert").tag(AppMode.alert)
                        Text("Silent Allow").tag(AppMode.silentAllow)
                        Text("Silent Deny").tag(AppMode.silentDeny)
                    }
                }
            }
            .formStyle(.grouped)
            Spacer(minLength: 0)
        }
    }

    private var helperSummary: String {
        switch state.helperInstallState {
        case .enabled: return state.helperConnected ? "Connected" : "Approved, connecting…"
        case .requiresApproval: return "Waiting for your approval"
        case .notRegistered, .unknown: return "Not installed"
        case .wrongLocation: return "Move PureSnitch to /Applications"
        case .notFound: return "Missing from this build"
        case .failed(let m): return "Failed: \(m)"
        }
    }

    private func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        } catch {
            state.appendLog(level: "error", message: "Login item change failed: \(error.localizedDescription)")
            launchAtLogin = SMAppService.mainApp.status == .enabled
        }
    }

    private var dnsTab: some View {
        Form {
            Section("DNS over HTTPS upstream") {
                TextField("DoH URL", text: $doh)
                    .onSubmit { state.helper.remote?.setDoHUpstream(url: doh) { _, _ in } }
                Text("Examples:").font(.caption).foregroundColor(.secondary)
                Text("https://cloudflare-dns.com/dns-query").font(.caption.monospaced())
                Text("https://dns.quad9.net/dns-query").font(.caption.monospaced())
                Text("https://dns.google/dns-query").font(.caption.monospaced())
            }
            Section("Local DNS proxy") {
                HStack {
                    Text("Status")
                    Spacer()
                    Text(state.dnsProxyEnabled ? "Running on port \(AppConstants.dnsProxyPort)" : "Not running")
                        .foregroundColor(.secondary)
                }
                Text("The DNS proxy runs inside the privileged helper and filters domain lookups against the enabled blocklists. It reports as running only once the helper confirms it.")
                    .font(.caption).foregroundColor(.secondary)
            }
        }
    }

    private var blocklistsTab: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Blocklists").font(.headline)
                Spacer()
                Button("Refresh All") { state.helper.refreshBlocklists() }
            }
            if state.blocklists.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("No blocklists loaded")
                        .font(.body).foregroundColor(.secondary)
                    Text(state.helperConnected
                         ? "Press Refresh All to download the default blocklists."
                         : "Blocklists live in the privileged helper. Approve the helper first — see the General tab.")
                        .font(.caption).foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .padding(.top, 8)
            }
            List(state.blocklists) { b in
                HStack {
                    Toggle("", isOn: Binding(
                        get: { b.enabled },
                        set: { newValue in
                            state.helper.remote?.enableBlocklist(idString: b.id.uuidString, enabled: newValue) { _, _ in }
                        }
                    ))
                    .labelsHidden()
                    VStack(alignment: .leading) {
                        Text(b.name).font(.body)
                        Text(b.url).font(.caption2).foregroundColor(.secondary).lineLimit(1)
                    }
                    Spacer()
                    Text("\(b.entryCount)").font(.caption.monospacedDigit())
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    private var profilesTab: some View {
        VStack(alignment: .leading) {
            Text("Profiles").font(.headline)
            if state.profiles.isEmpty {
                Text("No profiles yet. Profiles come from the privileged helper's rule database.")
                    .font(.caption).foregroundColor(.secondary)
            }
            ForEach(state.profiles) { p in
                HStack {
                    Image(systemName: p.icon)
                    Text(p.name)
                    Spacer()
                    if p.isActive {
                        PSChip("Active", color: PSTheme.accentGreen)
                    } else {
                        Button("Activate") {
                            state.activeProfile = p.name
                        }
                    }
                }.padding(.vertical, 4)
            }
        }
    }

    private var aboutTab: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 64)).foregroundColor(PSTheme.accent)
            Text("PureSnitch").font(.title.bold())
            Text("v\(AppConstants.version)").font(.subheadline).foregroundColor(.secondary)
            Text("Open-source application firewall for macOS.").font(.caption).foregroundColor(.secondary)
            Link("github.com/momenbasel/puresnitch", destination: URL(string: "https://github.com/momenbasel/puresnitch")!)
                .font(.caption)
            Text("MIT License · © 2026 Moamen Basel")
                .font(.caption2).foregroundColor(.secondary)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
