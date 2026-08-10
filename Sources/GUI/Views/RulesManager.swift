import SwiftUI
import AppKit

struct RulesManagerView: View {
    @EnvironmentObject var state: AppState
    @State private var selectedCategory: Category = .all
    @State private var searchText: String = ""
    @State private var selectedRule: Rule?

    enum Category: Hashable {
        case all
        case active
        case deny
        case recentChanges
        case recentlyUsed
        case temporary
        case unapproved
        case group(String)
        case blocklist(UUID)
    }

    var body: some View {
        VStack(spacing: 0) {
            HelperBanner()
            HStack(spacing: 0) {
                sidebar.frame(width: 220).background(PSTheme.bgSidebar)
                Divider().background(PSTheme.stroke)
                mainPane
                Divider().background(PSTheme.stroke)
                infoPane.frame(width: 240).background(PSTheme.bgSecondary)
            }
        }
        .background(PSTheme.bgPrimary)
        .preferredColorScheme(.dark)
    }

    private var sidebar: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 2) {
                sidebarHeader("Rules")
                navRow(.all, label: "All Rules", icon: "list.bullet", count: state.rules.count)
                navRow(.active, label: "Active", icon: "checkmark.circle.fill", color: PSTheme.accentGreen, count: state.rules.filter { $0.enabled && $0.action == .allow }.count)
                navRow(.deny, label: "Deny", icon: "minus.circle.fill", color: PSTheme.accentRed, count: state.rules.filter { $0.action == .deny }.count)
                navRow(.recentChanges, label: "Recent Changes", icon: "clock.fill", count: recentChangesCount)
                navRow(.recentlyUsed, label: "Recently Used", icon: "clock.arrow.circlepath", count: state.rules.filter { $0.lastUsedAt != nil }.count)
                navRow(.temporary, label: "Temporary", icon: "hourglass", color: PSTheme.accentYellow, count: state.rules.filter { $0.temporary }.count)
                navRow(.unapproved, label: "Unapproved", icon: "questionmark.circle.fill", count: state.rules.filter { $0.action == .ask }.count, badge: true)

                sidebarHeader("Rule Groups").padding(.top, 8)
                groupRow("iCloud Services", icon: "icloud.fill")
                groupRow("macOS Services", icon: "applelogo")
                groupRow("Apple Apps", icon: "app.gift")
                groupRow("Third Party Apps", icon: "shippingbox")

                sidebarHeader("Blocklists").padding(.top, 8)
                ForEach(state.blocklists) { b in
                    blocklistRow(b)
                }
            }
            .padding(.vertical, 6)
        }
    }

    private func sidebarHeader(_ s: String) -> some View {
        HStack {
            Text(s).font(.system(size: 11, weight: .semibold)).foregroundColor(PSTheme.textMuted)
            Spacer()
        }.padding(.horizontal, 10).padding(.top, 6)
    }

    private func navRow(_ cat: Category, label: String, icon: String, color: Color = PSTheme.accentBlue, count: Int, badge: Bool = false) -> some View {
        Button(action: { selectedCategory = cat }) {
            HStack(spacing: 8) {
                Image(systemName: icon).foregroundColor(color)
                    .font(.system(size: 12)).frame(width: 16)
                Text(label).font(.system(size: 12)).foregroundColor(PSTheme.textPrimary)
                Spacer()
                if count > 0 {
                    Text("\(count)").font(.system(size: 10, weight: .semibold))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .foregroundColor(.white)
                        .background(badge ? PSTheme.accentBlue : PSTheme.bgTertiary)
                        .clipShape(Capsule())
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 4)
            .background(selectedCategory == cat ? PSTheme.accent.opacity(0.18) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 5))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func groupRow(_ label: String, icon: String) -> some View {
        Button(action: { selectedCategory = .group(label) }) {
            HStack(spacing: 8) {
                Toggle("", isOn: .constant(true))
                    .toggleStyle(.checkbox)
                    .controlSize(.mini)
                    .labelsHidden()
                Image(systemName: icon).foregroundColor(PSTheme.accent).frame(width: 16)
                Text(label).font(.system(size: 12)).foregroundColor(PSTheme.textPrimary)
                Spacer()
            }
            .padding(.horizontal, 10).padding(.vertical, 3)
            .background(selectedCategory == .group(label) ? PSTheme.accent.opacity(0.18) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 5))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func blocklistRow(_ b: BlocklistInfo) -> some View {
        Button(action: { selectedCategory = .blocklist(b.id) }) {
            HStack(spacing: 8) {
                Toggle("", isOn: Binding(get: { b.enabled }, set: { _ in }))
                    .toggleStyle(.checkbox)
                    .controlSize(.mini)
                    .labelsHidden()
                Image(systemName: "shield.lefthalf.filled").foregroundColor(PSTheme.accentRed).frame(width: 16)
                Text(b.name).font(.system(size: 12)).foregroundColor(PSTheme.textPrimary).lineLimit(1)
                Spacer()
            }
            .padding(.horizontal, 10).padding(.vertical, 3)
            .background(selectedCategory == .blocklist(b.id) ? PSTheme.accent.opacity(0.18) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 5))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var mainPane: some View {
        VStack(spacing: 0) {
            toolbar
            Divider().background(PSTheme.stroke)
            rulesList
        }
    }

    private var toolbar: some View {
        HStack(spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundColor(PSTheme.textMuted).font(.system(size: 11))
                TextField("Search", text: $searchText).textFieldStyle(.plain).foregroundColor(PSTheme.textPrimary)
            }
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(PSTheme.bgTertiary)
            .clipShape(RoundedRectangle(cornerRadius: 6))
            Spacer()
            Button(action: {}) { Image(systemName: "tray.and.arrow.down.fill") }.buttonStyle(.borderless)
            Button(action: {}) { Image(systemName: "tray.and.arrow.up.fill") }.buttonStyle(.borderless)
            Button(action: {}) { Image(systemName: "plus") }.buttonStyle(.borderless)
        }
        .padding(8)
        .foregroundColor(PSTheme.textSecondary)
    }

    private var rulesList: some View {
        VStack(spacing: 0) {
            HStack {
                Text(categoryTitle).font(.system(size: 22, weight: .bold)).foregroundColor(PSTheme.textPrimary)
                Text("\(filteredRules.count) rules").font(.system(size: 11)).foregroundColor(PSTheme.textMuted)
                Spacer()
            }.padding(.horizontal, 14).padding(.vertical, 10)

            HStack {
                Text("Process").font(.system(size: 10, weight: .semibold)).foregroundColor(PSTheme.textMuted)
                Spacer()
                Text("Rule").font(.system(size: 10, weight: .semibold)).foregroundColor(PSTheme.textMuted)
            }
            .padding(.horizontal, 14)

            Divider().background(PSTheme.stroke)

            if filteredRules.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(Array(filteredRules.enumerated()), id: \.element.id) { idx, r in
                            RuleRowView(rule: r, alt: idx % 2 == 1, selected: selectedRule?.id == r.id)
                                .contentShape(Rectangle())
                                .onTapGesture { selectedRule = r }
                        }
                    }
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Spacer()
            Image(systemName: emptyIcon)
                .font(.system(size: 38)).foregroundColor(PSTheme.textMuted)
            Text(emptyTitle)
                .font(.system(size: 15, weight: .semibold)).foregroundColor(PSTheme.textSecondary)
            Text(emptySubtitle)
                .font(.system(size: 12)).foregroundColor(PSTheme.textMuted)
                .multilineTextAlignment(.center).frame(maxWidth: 360)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyIcon: String {
        if case .blocklist = selectedCategory { return "shield.lefthalf.filled" }
        if !state.helperConnected { return "bolt.horizontal.circle" }
        return "list.bullet"
    }

    private var emptyTitle: String {
        if case .blocklist(let id) = selectedCategory {
            return state.blocklists.first(where: { $0.id == id })?.name ?? "Blocklist"
        }
        if !state.helperConnected { return "Helper not running" }
        if state.rules.isEmpty { return "No rules yet" }
        return "Nothing in \(categoryTitle)"
    }

    private var emptySubtitle: String {
        if case .blocklist(let id) = selectedCategory {
            let count = state.blocklists.first(where: { $0.id == id })?.entryCount ?? 0
            return "This blocklist contains \(count) domain entries. Enable or refresh it in Settings → Blocklists."
        }
        if !state.helperConnected {
            return "Rules are managed by the PureSnitch helper. Approve it in System Settings → General → Login Items — this window fills in on its own once it connects."
        }
        if state.rules.isEmpty {
            return "Rules are created automatically when you allow or deny a connection alert."
        }
        return "No rules match this filter."
    }

    private var categoryTitle: String {
        switch selectedCategory {
        case .all: return "All Rules"
        case .active: return "Active"
        case .deny: return "Deny"
        case .recentChanges: return "Recent Changes"
        case .recentlyUsed: return "Recently Used"
        case .temporary: return "Temporary"
        case .unapproved: return "Unapproved"
        case .group(let n): return n
        case .blocklist(let id): return state.blocklists.first(where: { $0.id == id })?.name ?? "Blocklist"
        }
    }

    private var recentCutoff: Date { Date().addingTimeInterval(-7 * 24 * 3600) }
    private var recentChangesCount: Int { state.rules.filter { $0.createdAt >= recentCutoff }.count }

    private var filteredRules: [Rule] {
        var rules = state.rules
        switch selectedCategory {
        case .all:
            break
        case .active:
            rules = rules.filter { $0.enabled && $0.action == .allow }
        case .deny:
            rules = rules.filter { $0.action == .deny }
        case .temporary:
            rules = rules.filter { $0.temporary }
        case .unapproved:
            rules = rules.filter { $0.action == .ask }
        case .recentChanges:
            rules = rules.filter { $0.createdAt >= recentCutoff }
                .sorted { $0.createdAt > $1.createdAt }
        case .recentlyUsed:
            rules = rules.filter { $0.lastUsedAt != nil }
                .sorted { ($0.lastUsedAt ?? .distantPast) > ($1.lastUsedAt ?? .distantPast) }
        case .group(let name):
            rules = rules.filter { $0.groupName == name }
        case .blocklist:
            // Blocklists are domain sets, not per-process rules; shown as info.
            rules = []
        }
        if !searchText.isEmpty {
            rules = rules.filter {
                ($0.processName ?? "").localizedCaseInsensitiveContains(searchText) ||
                ($0.remoteHost ?? "").localizedCaseInsensitiveContains(searchText)
            }
        }
        return rules
    }

    private var infoPane: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "info.circle.fill").foregroundColor(PSTheme.accentBlue)
                Text("Information").font(.system(size: 14, weight: .semibold)).foregroundColor(PSTheme.textPrimary)
                Spacer()
            }
            if let r = selectedRule {
                ruleDetails(r)
            } else {
                Text("The filtering behavior of PureSnitch is defined by the rules listed here.")
                    .font(.system(size: 12)).foregroundColor(PSTheme.textSecondary)
                Text("Select a rule to see its details. See the PureSnitch Help, chapter [Anatomy of a rule](https://github.com/momenbasel/puresnitch#anatomy-of-a-rule) for more information.")
                    .font(.system(size: 11)).foregroundColor(PSTheme.textMuted)
                Spacer()
            }
        }
        .padding(14)
    }

    @ViewBuilder
    private func ruleDetails(_ r: Rule) -> some View {
        Divider().background(PSTheme.stroke)
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                infoField("Process", r.processName ?? "Any Process")
                if let p = r.processPath, !p.isEmpty { infoField("Path", p) }
                if let b = r.processBundleId, !b.isEmpty { infoField("Bundle ID", b) }
                infoField("Host", ruleHost(r))
                if let port = r.remotePort, port > 0 { infoField("Port", "\(port)") }
                infoField("Direction", r.direction.rawValue.capitalized)
                infoField("Action", r.action.rawValue.capitalized)
                infoField("Scope", r.scope.rawValue.capitalized)
                infoField("Priority", "\(r.priority)")
                infoField("Profile", r.profile)
                infoField("Status", r.enabled ? "Enabled" : "Disabled")
                infoField("Hits", "\(r.hitCount)")
                if let n = r.notes, !n.isEmpty { infoField("Notes", n) }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        HStack {
            Button(r.enabled ? "Disable" : "Enable") { toggleRule(r) }
                .buttonStyle(.bordered)
            Spacer()
            Button(role: .destructive) { removeRule(r) } label: { Text("Remove") }
                .buttonStyle(.borderedProminent).tint(.red)
        }
    }

    private func ruleHost(_ r: Rule) -> String {
        if let h = r.remoteHost, !h.isEmpty { return h }
        if let ip = r.remoteIP, !ip.isEmpty { return ip }
        return "Any"
    }

    private func infoField(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label).font(.system(size: 10, weight: .semibold)).foregroundColor(PSTheme.textMuted)
            Text(value).font(.system(size: 12)).foregroundColor(PSTheme.textPrimary)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func toggleRule(_ r: Rule) {
        var copy = r
        copy.enabled.toggle()
        state.helper.addRule(copy)   // upsert
        state.refreshRules()
        selectedRule = copy
    }

    private func removeRule(_ r: Rule) {
        state.helper.removeRule(id: r.id)
        state.refreshRules()
        selectedRule = nil
    }
}

struct RuleRowView: View {
    let rule: Rule
    let alt: Bool
    let selected: Bool

    var body: some View {
        HStack(spacing: 8) {
            if let icon = AppIcon.resolve(bundleId: rule.processBundleId, path: rule.processPath, name: rule.processName) {
                Image(nsImage: icon).resizable().frame(width: 16, height: 16)
            } else {
                Image(systemName: "person.crop.circle.dashed").foregroundColor(PSTheme.textSecondary)
                    .frame(width: 16)
            }
            Text(rule.processName ?? "Any Process").font(.system(size: 12)).foregroundColor(PSTheme.textPrimary)
                .lineLimit(1)
                .frame(width: 160, alignment: .leading)

            HStack(spacing: 6) {
                actionIcons
                if let n = ruleCount {
                    Text(n).font(.system(size: 10, weight: .semibold))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(PSTheme.bgTertiary)
                        .clipShape(Capsule())
                        .foregroundColor(PSTheme.textSecondary)
                }
                Image(systemName: "exclamationmark.shield.fill")
                    .foregroundColor(PSTheme.accentRed)
                    .font(.system(size: 11))
                Text(rule.notes ?? rule.remoteHost ?? "")
                    .font(.system(size: 12))
                    .foregroundColor(PSTheme.textPrimary)
                Spacer()
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 6)
        .background(selected ? PSTheme.accent.opacity(0.18) : (alt ? PSTheme.bgRowAlt : PSTheme.bgRow))
    }

    private var actionIcons: some View {
        HStack(spacing: 3) {
            iconCell(systemName: "person.fill", color: PSTheme.textSecondary)
            iconCell(systemName: "circle.fill", color: PSTheme.accentBlue)
            iconCell(systemName: "checkmark", color: PSTheme.accentGreen)
            iconCell(systemName: "xmark", color: PSTheme.accentRed)
        }
    }

    private func iconCell(systemName: String, color: Color) -> some View {
        ZStack {
            RoundedRectangle(cornerRadius: 3).fill(PSTheme.bgTertiary).frame(width: 14, height: 14)
            Image(systemName: systemName).font(.system(size: 8, weight: .bold)).foregroundColor(color)
        }
    }

    private var ruleCount: String? {
        if let host = rule.remoteHost, host.allSatisfy({ $0.isNumber || $0 == "," }) {
            return host
        }
        if rule.priority > 0 { return "\(rule.priority)" }
        return nil
    }
}
