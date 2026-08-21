import SwiftUI

struct ConnectionAlertView: View {
    @EnvironmentObject var state: AppState
    let alert: AppState.PendingAlert
    @State private var remember: Bool = true

    private var isIPv6Endpoint: Bool {
        Rule.isIPv6Address(alert.connection.remoteHost) ||
        Rule.isIPv6Address(alert.connection.remoteIP)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 32))
                    .foregroundColor(PSTheme.accent)
                VStack(alignment: .leading, spacing: 2) {
                    Text(alert.connection.processName.isEmpty ? "Unknown" : alert.connection.processName)
                        .font(.system(size: 16, weight: .bold)).foregroundColor(PSTheme.textPrimary)
                    Text("wants to connect to").font(.system(size: 12)).foregroundColor(PSTheme.textSecondary)
                }
                Spacer()
            }
            HStack(spacing: 8) {
                Image(systemName: "globe.americas").foregroundColor(PSTheme.accentBlue)
                Text(alert.connection.remoteHost.isEmpty ? alert.connection.remoteIP : alert.connection.remoteHost)
                    .font(.system(size: 14, weight: .semibold)).foregroundColor(PSTheme.textPrimary)
                if alert.connection.remotePort > 0 {
                    Text(":\(alert.connection.remotePort)").font(.system(size: 13, weight: .regular)).foregroundColor(PSTheme.textSecondary)
                }
                Spacer()
            }
            .padding(10)
            .background(PSTheme.bgTertiary)
            .clipShape(RoundedRectangle(cornerRadius: 8))

            VStack(alignment: .leading, spacing: 6) {
                Toggle("Remember this decision", isOn: $remember)
                    .toggleStyle(.checkbox)
                    .foregroundColor(PSTheme.textPrimary)
                    .disabled(isIPv6Endpoint)
                if isIPv6Endpoint {
                    Text("IPv6 rules are not supported in this release; this decision applies once.")
                        .font(.caption)
                        .foregroundColor(PSTheme.textSecondary)
                }
                if remember && !isIPv6Endpoint {
                    Text("The decision is saved permanently for this validated domain or IPv4 endpoint.")
                        .font(.caption)
                        .foregroundColor(PSTheme.textSecondary)
                }
            }

            HStack {
                Button("Deny") { state.resolveAlert(alert, allow: false, remember: remember && !isIPv6Endpoint) }
                    .keyboardShortcut(.cancelAction)
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                Spacer()
                Button("Allow") { state.resolveAlert(alert, allow: true, remember: remember && !isIPv6Endpoint) }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .tint(.green)
            }
        }
        .padding(18)
        .frame(width: 440)
        .background(PSTheme.bgPrimary)
        .preferredColorScheme(.dark)
        .onAppear {
            if isIPv6Endpoint { remember = false }
        }
    }
}

struct AlertOverlayContainer: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        ZStack {
            if let alert = state.pendingAlerts.first {
                Color.black.opacity(0.35).ignoresSafeArea()
                ConnectionAlertView(alert: alert).environmentObject(state)
            }
        }
    }
}

/// Content for the standalone floating alert panel (no dimming backdrop).
/// Shows the first pending alert; updates to the next one as each is resolved.
struct AlertWindowContent: View {
    @EnvironmentObject var state: AppState
    var body: some View {
        Group {
            if let alert = state.pendingAlerts.first {
                ConnectionAlertView(alert: alert).environmentObject(state)
            } else {
                Color.clear.frame(width: 440, height: 1)
            }
        }
    }
}
