import SwiftUI
import ServiceManagement

struct SettingsView: View {
    @EnvironmentObject var state: AppState
    @State private var doh = AppConstants.defaultDoHUpstream
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    @State private var showingRemoveHelperConfirmation = false

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
        .confirmationDialog(
            "Remove the privileged helper?",
            isPresented: $showingRemoveHelperConfirmation,
            titleVisibility: .visible
        ) {
            Button("Remove Helper", role: .destructive) {
                state.helper.unregisterDaemon()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("PureSnitch will stop monitoring until the helper is installed and approved again. Enforcement must already be off so removal cannot leave or silently clear firewall state.")
        }
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
                    if state.helperInstallState == .enabled {
                        Button("Remove Helper…", role: .destructive) {
                            showingRemoveHelperConfirmation = true
                        }
                        .disabled(removeHelperDisabled)
                        Text("Turn Enforcement Off and wait for both runtime components to stop before removing the helper.")
                            .font(.caption)
                            .foregroundColor(.secondary)
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
                    Toggle(
                        "Block traffic, don't just watch it",
                        isOn: Binding(
                            get: { state.enforcementEnabled },
                            set: { state.requestEnforcementDesired($0) }
                        )
                    )
                        .disabled(!state.helperConnected || !state.helperStatusLoaded || state.enforcementRequestInFlight || state.modeRequestInFlight)
                    HStack {
                        Text("Runtime status")
                        Spacer()
                        Text(enforcementRuntimeSummary).foregroundColor(.secondary)
                    }
                    Text("Experimental and off by default. This loads a pf firewall anchor and starts a local DNS proxy on port \(AppConstants.dnsProxyPort). PureSnitch does not change macOS DNS settings; DNS filtering applies only if you manually configure this Mac or an app to use the proxy. Leave this off for monitoring only.")
                        .font(.caption).foregroundColor(.secondary)
                }
                Section("Mode") {
                    Picker("Default mode", selection: Binding(get: { state.mode }, set: { state.setMode($0) })) {
                        Text("Alert").tag(AppMode.alert)
                        Text("Silent Allow").tag(AppMode.silentAllow)
                        Text("Silent Deny").tag(AppMode.silentDeny)
                    }
                    .disabled(!state.helperConnected || !state.helperStatusLoaded || state.enforcementRequestInFlight || state.modeRequestInFlight)
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

    private var removeHelperDisabled: Bool {
        !state.helperConnected
            || !state.helperStatusLoaded
            || state.enforcementEnabled
            || state.pfctlEnabled
            || state.dnsProxyEnabled
            || state.enforcementRequestInFlight
            || state.modeRequestInFlight
    }

    private var enforcementRuntimeSummary: String {
        if !state.helperConnected { return "Helper disconnected; runtime unknown" }
        if !state.helperStatusLoaded { return "Loading helper status…" }
        if state.enforcementRequestInFlight { return "Applying requested state…" }
        switch (state.pfctlEnabled, state.dnsProxyEnabled) {
        case (true, true): return "Firewall and DNS proxy active"
        case (true, false): return "Firewall active; DNS proxy inactive"
        case (false, true): return "DNS proxy active; firewall inactive"
        case (false, false): return state.enforcementEnabled ? "Requested; waiting for helper" : "Inactive"
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
                    Text(dnsRuntimeSummary)
                        .foregroundColor(.secondary)
                }
                Text("The proxy runs inside the privileged helper and filters queries sent directly to it. PureSnitch does not configure it as the macOS system resolver; manual DNS configuration is required. Status changes only after the helper confirms it.")
                    .font(.caption).foregroundColor(.secondary)
            }
        }
    }

    private var dnsRuntimeSummary: String {
        guard state.helperConnected, state.helperStatusLoaded else { return "Runtime unknown" }
        return state.dnsProxyEnabled ? "Running on port \(AppConstants.dnsProxyPort)" : "Not running"
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
            Text("Profiles (organizational only)").font(.headline)
            Text("PureSnitch 0.2.1 enforces only the default profile. Additional profiles can organize stored rules but cannot be activated.")
                .font(.caption).foregroundColor(.secondary)
            if state.profiles.isEmpty {
                Text("No profiles yet. Profiles come from the privileged helper's rule database.")
                    .font(.caption).foregroundColor(.secondary)
            }
            ForEach(state.profiles) { p in
                HStack {
                    Image(systemName: p.icon)
                    Text(p.name)
                    Spacer()
                    if p.name == "default" {
                        PSChip("Enforced", color: PSTheme.accentGreen)
                    } else {
                        PSChip("Stored only", color: PSTheme.textSecondary)
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
