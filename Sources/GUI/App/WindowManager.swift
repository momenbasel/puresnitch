import AppKit
import SwiftUI
import Combine

@MainActor
final class WindowManager {
    private let state: AppState
    private weak var networkMonitorWindow: NSWindow?
    private weak var rulesWindow: NSWindow?
    private weak var settingsWindow: NSWindow?
    private var alertWindow: NSWindow?
    private var alertCancellable: AnyCancellable?

    init(state: AppState) {
        self.state = state
        observeAlerts()
    }

    // MARK: - Public windows

    func showNetworkMonitor() {
        if let w = networkMonitorWindow { focus(w); return }
        networkMonitorWindow = makeWindow(
            title: "Network Monitor",
            defaultSize: NSSize(width: 1100, height: 700),
            minSize: NSSize(width: 900, height: 550),
            autosaveName: "PureSnitch.NetworkMonitor",
            content: NetworkMonitorView().environmentObject(state)
        )
    }

    func showRulesManager() {
        if let w = rulesWindow { focus(w); return }
        rulesWindow = makeWindow(
            title: "Rules",
            defaultSize: NSSize(width: 1000, height: 650),
            minSize: NSSize(width: 820, height: 500),
            autosaveName: "PureSnitch.Rules",
            content: RulesManagerView().environmentObject(state)
        )
    }

    func showSettings() {
        if let w = settingsWindow { focus(w); return }
        // Created manually rather than via the SwiftUI `Settings` scene: the
        // `showSettingsWindow:` action is unreliable for `.accessory`
        // (menu-bar-only) apps and was the reason Settings never appeared.
        settingsWindow = makeWindow(
            title: "Settings",
            defaultSize: NSSize(width: 560, height: 460),
            minSize: NSSize(width: 560, height: 460),
            autosaveName: "PureSnitch.Settings",
            content: SettingsView().environmentObject(state),
            resizable: false
        )
    }

    // MARK: - Window factory

    private func makeWindow<Content: View>(
        title: String,
        defaultSize: NSSize,
        minSize: NSSize,
        autosaveName: String,
        content: Content,
        resizable: Bool = true
    ) -> NSWindow {
        var style: NSWindow.StyleMask = [.titled, .closable, .miniaturizable, .fullSizeContentView]
        if resizable { style.insert(.resizable) }

        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: defaultSize),
            styleMask: style,
            backing: .buffered,
            defer: false
        )
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.title = title
        window.isReleasedWhenClosed = false
        window.minSize = minSize
        // Use `contentView` (NSHostingView) instead of `contentViewController`.
        // Assigning a hosting *controller* makes NSWindow resize itself to the
        // SwiftUI view's fitting size — which collapsed these windows to a
        // sliver. A hosting *view* keeps the size we set here, but only if we
        // also stop it exporting an intrinsic size: with `sizingOptions`
        // left at its default the window grew to the content's ideal height
        // (a 2101 pt tall Network Monitor) the moment a text-heavy banner was
        // added to it.
        let hosting = NSHostingView(rootView: content)
        hosting.sizingOptions = []
        hosting.autoresizingMask = [.width, .height]
        window.contentView = hosting
        window.setContentSize(defaultSize)

        // Persist + restore the window frame across launches. A stored frame
        // from a broken build can be larger than the screen, so fall back to a
        // centred default rather than restoring something unusable.
        window.setFrameAutosaveName(autosaveName)
        let visible = (window.screen ?? NSScreen.main)?.visibleFrame ?? .zero
        if !window.setFrameUsingName(autosaveName)
            || window.frame.width > visible.width + 1
            || window.frame.height > visible.height + 1 {
            window.setContentSize(defaultSize)
            window.center()
        }

        focus(window)
        return window
    }

    private func focus(_ window: NSWindow) {
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    // MARK: - Connection alerts

    private func observeAlerts() {
        alertCancellable = state.$pendingAlerts
            .receive(on: RunLoop.main)
            .sink { [weak self] alerts in
                self?.syncAlertWindow(hasAlert: !alerts.isEmpty)
            }
    }

    private func syncAlertWindow(hasAlert: Bool) {
        if hasAlert {
            if alertWindow == nil { presentAlertWindow() }
        } else {
            alertWindow?.close()
            alertWindow = nil
        }
    }

    private func presentAlertWindow() {
        // Use a hosting *controller* so the panel auto-sizes to the alert's
        // content — long process names / hostnames grow the card correctly.
        // (Reading NSHostingView.fittingSize before the view is laid out
        // returns zero and would clip the content.)
        let hosting = NSHostingController(rootView: AlertWindowContent().environmentObject(state))
        let window = NSPanel(contentViewController: hosting)
        window.styleMask = [.titled, .fullSizeContentView]
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        alertWindow = window
    }
}
