import AppKit
import SwiftUI
import Combine

@MainActor
final class MenubarController {
    private let state: AppState
    private let windows: WindowManager
    private var statusItem: NSStatusItem!
    private var popover: NSPopover!
    private var trafficCancellable: AnyCancellable?

    init(state: AppState, windows: WindowManager) {
        self.state = state
        self.windows = windows
    }

    func install() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem.button {
            button.imagePosition = .imageOnly
            button.action = #selector(handleClick(_:))
            button.target = self
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }

        popover = NSPopover()
        popover.behavior = .transient
        popover.animates = true
        let popoverView = MenubarPopoverView(close: { [weak self] in self?.popover.performClose(nil) })
            .environmentObject(state)
            .environmentObject(windows)
            .frame(width: 380, height: 540)
        popover.contentViewController = NSHostingController(rootView: popoverView)

        render()

        // Redraw on traffic, on helper health changes (the glyph reflects it)
        // and when the user toggles the speed readout in Settings.
        trafficCancellable = Publishers.MergeMany(
            state.$trafficHistory.map { _ in () }.eraseToAnyPublisher(),
            state.$helperConnected.map { _ in () }.eraseToAnyPublisher(),
            state.$helperInstallState.map { _ in () }.eraseToAnyPublisher(),
            state.$showSpeedsInMenuBar.map { _ in () }.eraseToAnyPublisher()
        )
        .receive(on: RunLoop.main)
        .sink { [weak self] _ in self?.render() }
    }

    @objc private func handleClick(_ sender: AnyObject?) {
        guard let button = statusItem.button else { return }
        if let event = NSApp.currentEvent, event.type == .rightMouseUp {
            showContextMenu()
            return
        }
        if popover.isShown {
            popover.performClose(sender)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    private func showContextMenu() {
        let menu = NSMenu()
        menu.addItem(makeItem("Network Monitor…", #selector(openMonitor), keyEq: "n"))
        menu.addItem(makeItem("Rules…", #selector(openRules), keyEq: "r"))
        menu.addItem(makeItem("Settings…", #selector(openSettings), keyEq: ","))
        menu.addItem(.separator())
        let modeMenu = NSMenu(title: "Mode")
        modeMenu.addItem(makeItem("Alert", #selector(modeAlert), keyEq: "", state: state.mode == .alert ? .on : .off))
        modeMenu.addItem(makeItem("Silent Allow", #selector(modeAllow), keyEq: "", state: state.mode == .silentAllow ? .on : .off))
        modeMenu.addItem(makeItem("Silent Deny", #selector(modeDeny), keyEq: "", state: state.mode == .silentDeny ? .on : .off))
        let modeItem = NSMenuItem(title: "Mode", action: nil, keyEquivalent: "")
        modeItem.submenu = modeMenu
        menu.addItem(modeItem)
        menu.addItem(.separator())
        menu.addItem(makeItem("Quit PureSnitch", #selector(quit), keyEq: "q"))
        statusItem.menu = menu
        statusItem.button?.performClick(nil)
        statusItem.menu = nil
    }

    private func makeItem(_ title: String, _ sel: Selector, keyEq: String, state: NSControl.StateValue = .off) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: sel, keyEquivalent: keyEq)
        item.target = self
        item.state = state
        return item
    }

    @objc private func openMonitor() { windows.showNetworkMonitor() }
    @objc private func openRules() { windows.showRulesManager() }
    @objc private func openSettings() { windows.showSettings() }
    @objc private func modeAlert() { state.setMode(.alert) }
    @objc private func modeAllow() { state.setMode(.silentAllow) }
    @objc private func modeDeny() { state.setMode(.silentDeny) }
    @objc private func quit() { NSApp.terminate(nil) }

    /// Draws the status item the way AppKit expects: a template symbol that the
    /// system recolours for light, dark, high-contrast and tinted menu bars.
    /// The previous version hand-drew pink and blue text into a non-template
    /// bitmap, which is what users saw as "the menu icon is 2 colours".
    private func render() {
        guard let button = statusItem.button else { return }

        let healthy = state.helperConnected
        let symbol = healthy ? "shield.lefthalf.filled" : "shield.slash"
        let config = NSImage.SymbolConfiguration(pointSize: 14, weight: .medium)
        let image = NSImage(systemSymbolName: symbol, accessibilityDescription: "PureSnitch")?
            .withSymbolConfiguration(config)
        image?.isTemplate = true
        button.image = image

        if state.showSpeedsInMenuBar {
            statusItem.length = NSStatusItem.variableLength
            button.imagePosition = .imageLeft
            button.font = .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
            button.title = " ↓\(compactSpeed(state.currentIn))  ↑\(compactSpeed(state.currentOut))"
        } else {
            statusItem.length = NSStatusItem.squareLength
            button.imagePosition = .imageOnly
            button.title = ""
        }

        button.toolTip = tooltip
        button.setAccessibilityLabel("PureSnitch — \(tooltip)")
    }

    private var tooltip: String {
        guard state.helperConnected else {
            switch state.helperInstallState {
            case .requiresApproval: return "Waiting for approval in System Settings › Login Items"
            case .wrongLocation: return "Move PureSnitch to your Applications folder"
            case .notFound: return "Helper missing from this build"
            case .failed(let m): return "Helper error: \(m)"
            default: return "Helper not running — no traffic is being monitored"
            }
        }
        return "↓ \(PSFormat.bytesPerSec(state.currentIn))  ↑ \(PSFormat.bytesPerSec(state.currentOut))"
    }

    private func compactSpeed(_ n: Int64) -> String {
        let b = Double(n)
        if b < 1024 { return "\(Int(b)) B/s" }
        if b < 1024 * 1024 { return String(format: "%.0f K/s", b/1024) }
        if b < 1024 * 1024 * 1024 { return String(format: "%.1f M/s", b/1024/1024) }
        return String(format: "%.1f G/s", b/1024/1024/1024)
    }
}

extension WindowManager: ObservableObject {}
