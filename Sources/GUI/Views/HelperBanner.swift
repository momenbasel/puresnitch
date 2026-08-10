import SwiftUI
import AppKit

/// The one piece of UI that keeps PureSnitch honest: when the privileged helper
/// isn't approved or isn't reachable, every panel in the app reads zero. Before
/// this banner existed that state was indistinguishable from "the app is
/// broken" — which is exactly what users reported.
struct HelperBanner: View {
    @EnvironmentObject var state: AppState
    /// Compact variant for the menu-bar popover.
    var compact: Bool = false

    var body: some View {
        if let info = BannerInfo(installState: state.helperInstallState,
                                 connected: state.helperConnected,
                                 needsRepair: state.helperNeedsRepair) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: info.icon)
                    .foregroundColor(info.tint)
                    .font(.system(size: compact ? 12 : 14, weight: .semibold))
                VStack(alignment: .leading, spacing: 3) {
                    Text(info.title)
                        .font(.system(size: compact ? 11 : 12, weight: .semibold))
                        .foregroundColor(PSTheme.textPrimary)
                    Text(info.detail)
                        .font(.system(size: compact ? 10 : 11))
                        .foregroundColor(PSTheme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                if let action = info.action {
                    Button(action.title) { action.run(state) }
                        .buttonStyle(.borderedProminent)
                        .controlSize(compact ? .small : .regular)
                }
            }
            .padding(.horizontal, compact ? 10 : 14)
            .padding(.vertical, compact ? 8 : 10)
            .background(info.tint.opacity(0.12))
            .overlay(Rectangle().frame(height: 1).foregroundColor(info.tint.opacity(0.35)), alignment: .bottom)
        }
    }
}

private struct BannerAction {
    let title: String
    let run: @MainActor (AppState) -> Void
}

@MainActor
private struct BannerInfo {
    let icon: String
    let tint: Color
    let title: String
    let detail: String
    let action: BannerAction?

    /// Returns nil when everything is healthy — no banner, no noise.
    init?(installState: HelperInstallState, connected: Bool, needsRepair: Bool) {
        switch installState {
        case .enabled where connected:
            return nil
        case .enabled where needsRepair:
            icon = "wrench.and.screwdriver.fill"
            tint = PSTheme.accentYellow
            title = "The helper needs repairing"
            detail = "It is approved but either not responding or left over from an older PureSnitch — usually after an in-place update. Repairing re-installs the background helper; macOS will ask you to approve it once more in Login Items."
            action = BannerAction(title: "Repair Helper") { $0.helper.repairHelper() }
        case .enabled:
            icon = "hourglass"
            tint = PSTheme.accentYellow
            title = "Connecting to the PureSnitch helper…"
            detail = "The helper is approved but hasn't answered yet. This usually clears within a few seconds."
            action = nil
        case .requiresApproval:
            icon = "exclamationmark.triangle.fill"
            tint = PSTheme.accentYellow
            title = "PureSnitch needs your approval to monitor traffic"
            detail = "Open System Settings › General › Login Items & Extensions and switch PureSnitch on under \"Allow in the Background\". Until then no connections, rules or traffic can be shown."
            action = BannerAction(title: "Open Login Items") { $0.helper.openLoginItemsSettings() }
        case .notRegistered, .unknown:
            icon = "bolt.horizontal.circle.fill"
            tint = PSTheme.accentYellow
            title = "The PureSnitch helper isn't installed yet"
            detail = "The helper runs the traffic monitor and the firewall rules. Install it to start seeing connections."
            action = BannerAction(title: "Install Helper") { $0.helper.registerDaemon() }
        case .wrongLocation:
            icon = "arrow.down.app.fill"
            tint = PSTheme.accentRed
            title = "Move PureSnitch to your Applications folder"
            detail = "macOS refuses to install background helpers for apps launched from a disk image or the Downloads folder. Drag PureSnitch.app into Applications, then open it from there."
            action = BannerAction(title: "Reveal in Finder") { _ in
                NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL])
            }
        case .notFound:
            icon = "xmark.octagon.fill"
            tint = PSTheme.accentRed
            title = "The helper is missing from this copy of PureSnitch"
            detail = "This build has no privileged helper bundled. Download PureSnitch again from the official releases page."
            action = nil
        case .failed(let message):
            icon = "xmark.octagon.fill"
            tint = PSTheme.accentRed
            title = "Helper installation failed"
            detail = "\(message) Move PureSnitch into /Applications and try again."
            action = BannerAction(title: "Retry") { $0.helper.registerDaemon() }
        }
    }
}
