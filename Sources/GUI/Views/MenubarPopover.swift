import SwiftUI

struct MenubarPopoverView: View {
    @EnvironmentObject var state: AppState
    @EnvironmentObject var windows: WindowManager
    let close: () -> Void
    @State private var showModePicker = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerBar
                .padding(.horizontal, 12).padding(.top, 12).padding(.bottom, 8)

            HelperBanner(compact: true)

            trafficGraph
                .padding(.horizontal, 12)

            Text("Recent Network Activity")
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(PSTheme.textSecondary)
                .padding(.horizontal, 16).padding(.top, 14).padding(.bottom, 4)

            recentActivityList

            HStack {
                deniedRow
            }
            .padding(.horizontal, 12).padding(.vertical, 6)

            Divider().background(PSTheme.stroke)

            VStack(alignment: .leading, spacing: 0) {
                Button(action: { close(); windows.showRulesManager() }) {
                    HStack {
                        Text("Manage Rules…").font(.system(size: 13))
                        Spacer()
                    }
                    .contentShape(Rectangle())
                    .padding(.horizontal, 16).padding(.vertical, 8)
                }
                .buttonStyle(.plain).foregroundColor(PSTheme.textPrimary)

                Button(action: { close(); windows.showNetworkMonitor() }) {
                    HStack {
                        Text("Network Monitor…").font(.system(size: 13))
                        Spacer()
                    }
                    .contentShape(Rectangle())
                    .padding(.horizontal, 16).padding(.vertical, 8)
                }
                .buttonStyle(.plain).foregroundColor(PSTheme.textPrimary)

                Button(action: { close(); windows.showSettings() }) {
                    HStack {
                        Text("PureSnitch Settings…").font(.system(size: 13))
                        Spacer()
                    }
                    .contentShape(Rectangle())
                    .padding(.horizontal, 16).padding(.vertical, 8)
                }
                .buttonStyle(.plain).foregroundColor(PSTheme.textPrimary)
            }
            .padding(.bottom, 8)
        }
        .frame(width: 380, height: 540)
        .background(PSTheme.bgPrimary)
    }

    private var headerBar: some View {
        HStack(spacing: 8) {
            ModeButton(mode: state.mode, showing: $showModePicker)
                .popover(isPresented: $showModePicker, arrowEdge: .bottom) {
                    ModePicker(current: state.mode) { m in
                        state.setMode(m)
                        showModePicker = false
                    }
                }
            Spacer()
            Button(action: { close(); windows.showSettings() }) {
                Image(systemName: "gearshape.fill")
                    .font(.system(size: 14))
                    .foregroundColor(PSTheme.textSecondary)
                    .frame(width: 32, height: 32)
                    .background(PSTheme.bgTertiary)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
            }
            .buttonStyle(.plain)
            .help("PureSnitch Settings")
            Button(action: { close(); windows.showNetworkMonitor() }) {
                Image(systemName: "globe")
                    .font(.system(size: 14))
                    .foregroundColor(.white)
                    .frame(width: 32, height: 32)
                    .background(Color(red: 0.30, green: 0.55, blue: 1.0))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
            }
            .buttonStyle(.plain)
            .help("Network Monitor")
        }
    }

    private var trafficGraph: some View {
        ZStack(alignment: .topLeading) {
            RoundedRectangle(cornerRadius: 10)
                .fill(PSTheme.bgTertiary)
            TrafficBarsChart(history: state.trafficHistory)
                .padding(8)
            VStack(alignment: .leading) {
                HStack {
                    Text(PSFormat.bytes(state.totalOut))
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 6).padding(.vertical, 3)
                        .background(Color.purple.opacity(0.45))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                    Spacer()
                }
                Spacer()
                HStack {
                    Text(PSFormat.bytes(state.totalIn))
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 6).padding(.vertical, 3)
                        .background(Color.blue.opacity(0.45))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                    Spacer()
                }
                HStack {
                    Text("5 minutes ago")
                        .font(.system(size: 10))
                        .foregroundColor(PSTheme.textMuted)
                    Spacer()
                    Text("now")
                        .font(.system(size: 10))
                        .foregroundColor(PSTheme.textMuted)
                }
            }
            .padding(10)
        }
        .frame(height: 160)
    }

    private var recentActivityList: some View {
        VStack(spacing: 0) {
            ForEach(uniqueRecentProcesses().prefix(3)) { ps in
                HStack(spacing: 10) {
                    if let icon = ps.icon {
                        Image(nsImage: icon).resizable().frame(width: 18, height: 18)
                    } else {
                        Image(systemName: "app.dashed").foregroundColor(PSTheme.textSecondary)
                            .frame(width: 18, height: 18)
                    }
                    Text(ps.name).font(.system(size: 13))
                        .foregroundColor(PSTheme.textPrimary)
                    Spacer()
                }
                .padding(.horizontal, 16).padding(.vertical, 5)
            }
        }
    }

    private var deniedRow: some View {
        Button(action: { close(); windows.showNetworkMonitor() }) {
            HStack {
                ZStack {
                    Circle().fill(PSTheme.accentRed)
                    Text("\(state.deniedCount)").font(.system(size: 11, weight: .bold)).foregroundColor(.white)
                }.frame(width: 22, height: 22)
                Text("Recently Denied")
                    .font(.system(size: 13))
                    .foregroundColor(PSTheme.textPrimary)
                Spacer()
                Image(systemName: "chevron.right").foregroundColor(PSTheme.textMuted)
            }
            .contentShape(Rectangle())
            .padding(.horizontal, 4).padding(.vertical, 4)
        }
        .buttonStyle(.plain)
    }

    private func uniqueRecentProcesses() -> [AppState.ProcessStats] {
        state.topProcesses
    }
}

struct ModeButton: View {
    let mode: AppMode
    @Binding var showing: Bool
    var body: some View {
        Button(action: { showing.toggle() }) {
            HStack(spacing: 8) {
                ZStack {
                    Circle().fill(modeColor)
                    Image(systemName: modeIcon).font(.system(size: 11, weight: .bold)).foregroundColor(.white)
                }.frame(width: 24, height: 24)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Mode").font(.system(size: 10)).foregroundColor(PSTheme.textMuted)
                    Text(modeLabel).font(.system(size: 13, weight: .semibold)).foregroundColor(PSTheme.textPrimary)
                }
            }
            .padding(.horizontal, 8).padding(.vertical, 4)
            .background(PSTheme.bgTertiary)
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }
    private var modeColor: Color {
        switch mode {
        case .alert: return PSTheme.accentYellow
        case .silentAllow: return PSTheme.accentGreen
        case .silentDeny: return PSTheme.accentRed
        }
    }
    private var modeIcon: String {
        switch mode {
        case .alert: return "bell.fill"
        case .silentAllow: return "checkmark"
        case .silentDeny: return "xmark"
        }
    }
    private var modeLabel: String {
        switch mode {
        case .alert: return "Alert"
        case .silentAllow: return "Silent Allow"
        case .silentDeny: return "Silent Deny"
        }
    }
}

struct ModePicker: View {
    let current: AppMode
    let onPick: (AppMode) -> Void
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "chevron.left").foregroundColor(PSTheme.textSecondary)
                Text("Mode").font(.system(size: 14, weight: .semibold))
                    .foregroundColor(PSTheme.textPrimary)
                Spacer()
            }
            .padding(.horizontal, 12).padding(.vertical, 10)
            .background(PSTheme.bgTertiary)
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                pickerRow(.alert, "Alert", "bell.fill", PSTheme.accentYellow)
                pickerRow(.silentAllow, "Silent Allow", "checkmark", PSTheme.accentGreen)
                pickerRow(.silentDeny, "Silent Deny", "xmark", PSTheme.accentRed)
            }
            .padding(.vertical, 8)
        }
        .frame(width: 240)
        .background(PSTheme.bgPrimary)
    }
    private func pickerRow(_ m: AppMode, _ label: String, _ icon: String, _ color: Color) -> some View {
        Button(action: { onPick(m) }) {
            HStack(spacing: 12) {
                if current == m {
                    Image(systemName: "checkmark").font(.system(size: 11, weight: .bold))
                        .foregroundColor(PSTheme.textPrimary)
                        .frame(width: 14)
                } else {
                    Spacer().frame(width: 14)
                }
                ZStack {
                    Circle().fill(color)
                    Image(systemName: icon).font(.system(size: 11, weight: .bold)).foregroundColor(.white)
                }.frame(width: 22, height: 22)
                Text(label).font(.system(size: 13)).foregroundColor(PSTheme.textPrimary)
                Spacer()
            }
            .contentShape(Rectangle())
            .padding(.horizontal, 12).padding(.vertical, 6)
        }
        .buttonStyle(.plain)
    }
}

struct TrafficBarsChart: View {
    let history: [TrafficSample]
    var body: some View {
        GeometryReader { geo in
            let samples = Array(history.suffix(80))
            let count = max(samples.count, 1)
            let availW = geo.size.width
            let barW = max(2, (availW - CGFloat(count - 1) * 1.5) / CGFloat(count))
            let midY = geo.size.height / 2
            let maxIn = max(1, CGFloat(samples.map { $0.bytesIn }.max() ?? 1))
            let maxOut = max(1, CGFloat(samples.map { $0.bytesOut }.max() ?? 1))
            ZStack(alignment: .center) {
                HStack(alignment: .center, spacing: 1.5) {
                    ForEach(0..<samples.count, id: \.self) { i in
                        let s = samples[i]
                        VStack(spacing: 0) {
                            Rectangle()
                                .fill(LinearGradient(colors: [Color.purple.opacity(0.95), Color.purple.opacity(0.7)], startPoint: .top, endPoint: .bottom))
                                .frame(width: barW, height: max(2, CGFloat(s.bytesOut)/maxOut * midY * 0.95))
                            Rectangle()
                                .fill(LinearGradient(colors: [Color.blue.opacity(0.7), Color.blue.opacity(0.95)], startPoint: .top, endPoint: .bottom))
                                .frame(width: barW, height: max(2, CGFloat(s.bytesIn)/maxIn * midY * 0.95))
                        }
                    }
                }
            }
        }
    }
}
