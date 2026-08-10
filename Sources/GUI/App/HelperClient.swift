import Foundation
import ServiceManagement
import AppKit

/// Where the privileged helper stands from the user's point of view. macOS
/// registers the daemon on first launch but leaves it *disabled* until the user
/// approves it in System Settings; until then every helper call no-ops and the
/// whole app reads zero. This enum is what the UI shows instead of pretending
/// nothing is wrong.
enum HelperInstallState: Equatable {
    /// Not asked yet.
    case unknown
    /// Registered with launchd but waiting for the user to switch it on in
    /// System Settings › General › Login Items & Extensions.
    case requiresApproval
    /// Approved and running; XPC should be reachable.
    case enabled
    /// Registration was never attempted or was removed.
    case notRegistered
    /// The daemon plist isn't where macOS expects it (broken/unsigned build).
    case notFound
    /// The app is running from the disk image, Downloads, or anywhere else that
    /// isn't an Applications folder. macOS refuses to install background
    /// helpers from there, so registration is not even attempted.
    case wrongLocation
    /// register() itself failed; carries the message from macOS.
    case failed(String)

    var isHealthy: Bool { self == .enabled }
}

@MainActor
final class HelperClient: NSObject, ObservableObject {
    @Published var connected: Bool = false
    @Published var status: HelperStatus?
    @Published var installState: HelperInstallState = .unknown {
        didSet { state?.helperInstallState = installState }
    }

    private var connection: NSXPCConnection?
    private var didBootstrap = false
    private var pollTimer: Timer?
    private var isRepairing = false
    private var enabledButSilentSince: Date?
    /// Approved but unreachable for long enough that re-registering is worth
    /// offering. Never acted on automatically — see startPolling().
    /// Version string reported by the running daemon, when it answers at all.
    @Published var helperVersion: String?
    @Published var needsRepair = false {
        didSet { state?.helperNeedsRepair = needsRepair }
    }
    weak var state: AppState?

    private var service: SMAppService? {
        guard #available(macOS 13.0, *) else { return nil }
        return SMAppService.daemon(plistName: "io.moamenbasel.puresnitch.helper.plist")
    }

    /// True when the bundle lives somewhere macOS will accept a background
    /// helper from. Launching straight off the mounted DMG is the single most
    /// common way this app ends up looking dead.
    static var isInApplicationsFolder: Bool {
        let path = Bundle.main.bundleURL.resolvingSymlinksInPath().path
        if path.hasPrefix("/Applications/") { return true }
        let userApps = (NSHomeDirectory() as NSString).appendingPathComponent("Applications") + "/"
        return path.hasPrefix(userApps)
    }

    /// Registers the privileged helper as a launchd daemon via SMAppService.
    /// Without this the XPC mach service never exists, so every helper call
    /// silently no-ops (the root cause of "no rules / no traffic"). Requires a
    /// signed build; the user approves it in System Settings → Login Items.
    func registerDaemon() {
        guard Self.isInApplicationsFolder else { installState = .wrongLocation; return }
        guard let service else { installState = .notRegistered; return }
        switch service.status {
        case .enabled:
            installState = .enabled
            return
        case .requiresApproval:
            // Calling register() again here throws EPERM and tells the user
            // nothing useful — the item exists, it just isn't switched on yet.
            installState = .requiresApproval
            return
        default:
            break
        }
        do {
            try service.register()
            refreshInstallState()
        } catch {
            let ns = error as NSError
            installState = .failed(ns.localizedFailureReason ?? ns.localizedDescription)
            state?.appendLog(level: "error", message: "Helper registration failed: \(ns.localizedDescription)")
        }
    }

    /// Re-reads the launchd registration so the UI can drop the banner as soon
    /// as the user flips the switch in System Settings.
    func refreshInstallState() {
        guard Self.isInApplicationsFolder else { installState = .wrongLocation; return }
        guard let service else { installState = .notRegistered; return }
        switch service.status {
        case .enabled: installState = .enabled
        case .requiresApproval: installState = .requiresApproval
        case .notRegistered: installState = .notRegistered
        case .notFound: installState = .notFound
        @unknown default: installState = .unknown
        }
    }

    /// Opens the exact System Settings pane where the daemon is approved.
    func openLoginItemsSettings() {
        if #available(macOS 13.0, *) {
            SMAppService.openSystemSettingsLoginItems()
        } else {
            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")!)
        }
    }

    /// Removes the launchd registration (used by "Reinstall helper").
    func unregisterDaemon() {
        service?.unregister { [weak self] _ in
            Task { @MainActor in self?.refreshInstallState() }
        }
    }

    /// Re-registers the daemon. After the app bundle is replaced (an update, or
    /// a reinstall over the top) macOS keeps the Background Item approved but
    /// launchd no longer has the job, so `status` reads `.enabled` while
    /// nothing is listening. Unregistering and registering again is Apple's
    /// prescribed repair for exactly that state.
    func repairHelper() {
        guard let service else { return }
        isRepairing = true
        service.unregister { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                do { try service.register() } catch {
                    let ns = error as NSError
                    self.installState = .failed(ns.localizedFailureReason ?? ns.localizedDescription)
                }
                self.refreshInstallState()
                self.isRepairing = false
                self.reconnectAndPing()
            }
        }
    }

    func connect() {
        let conn = NSXPCConnection(machServiceName: AppConstants.xpcMachServiceName, options: [.privileged])
        conn.remoteObjectInterface = HelperBridge.remoteInterface()
        conn.exportedInterface = HelperBridge.exportedInterface()
        conn.exportedObject = HelperEventReceiver(state: state)
        conn.invalidationHandler = { [weak self] in
            Task { @MainActor in self?.setConnected(false) }
        }
        conn.interruptionHandler = { [weak self] in
            Task { @MainActor in self?.setConnected(false) }
        }
        conn.resume()
        self.connection = conn
        ping()
        startPolling()
    }

    /// Keeps checking registration + reachability. Approval happens outside the
    /// app (System Settings), so without polling the user has to relaunch to
    /// see anything change — which reads as "the app does nothing".
    private func startPolling() {
        pollTimer?.invalidate()
        let timer = Timer(timeInterval: 3.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, !self.isRepairing else { return }
                self.refreshInstallState()
                guard !self.connected else {
                    self.enabledButSilentSince = nil
                    self.needsRepair = false
                    return
                }
                self.reconnectAndPing()

                // Approved but silent (typically after an in-place app update,
                // where the Background Item stays approved but launchd has no
                // job). Surface it after a grace period and let the user decide:
                // repairing means unregister + register, and unregister REVOKES
                // the existing approval, so doing it automatically could throw
                // away a good approval just because XPC was slow to come up.
                guard self.installState == .enabled else {
                    self.enabledButSilentSince = nil
                    self.needsRepair = false
                    return
                }
                let since = self.enabledButSilentSince ?? Date()
                self.enabledButSilentSince = since
                self.needsRepair = Date().timeIntervalSince(since) > 20
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        pollTimer = timer
    }

    private func reconnectAndPing() {
        // A connection made before the daemon existed stays invalid forever, so
        // rebuild it rather than pinging a dead proxy.
        if connection == nil || installState == .enabled {
            connection?.invalidate()
            let conn = NSXPCConnection(machServiceName: AppConstants.xpcMachServiceName, options: [.privileged])
            conn.remoteObjectInterface = HelperBridge.remoteInterface()
            conn.exportedInterface = HelperBridge.exportedInterface()
            conn.exportedObject = HelperEventReceiver(state: state)
            conn.invalidationHandler = { [weak self] in Task { @MainActor in self?.setConnected(false) } }
            conn.interruptionHandler = { [weak self] in Task { @MainActor in self?.setConnected(false) } }
            conn.resume()
            connection = conn
        }
        ping()
    }

    var remote: HelperProtocol? {
        connection?.remoteObjectProxyWithErrorHandler { _ in } as? HelperProtocol
    }

    private func setConnected(_ value: Bool) {
        let wasConnected = connected
        connected = value
        state?.helperConnected = value
        guard value, !wasConnected else { return }
        // First reachable connection runs the full bootstrap; later
        // reconnections only refresh rules so we don't re-run startMonitoring /
        // installPF and duplicate the helper's monitors.
        if didBootstrap {
            state?.refreshRules()
        } else {
            didBootstrap = true
            state?.bootstrap()
        }
    }

    func ping() {
        remote?.getVersion { [weak self] version in
            Task { @MainActor in
                guard let self else { return }
                guard !version.isEmpty else { self.setConnected(false); return }
                // A helper left over from an older install answers happily but
                // speaks a different protocol. Treat that as "not healthy" and
                // offer the repair rather than silently running mismatched code.
                if version != AppConstants.version {
                    self.helperVersion = version
                    self.needsRepair = true
                    self.setConnected(false)
                    return
                }
                self.helperVersion = version
                self.setConnected(true)
            }
        }
        remote?.getStatus { [weak self] data in
            let status = try? JSONDecoder().decode(HelperStatus.self, from: data)
            Task { @MainActor in self?.status = status }
        }
    }

    func setMode(_ m: AppMode) {
        remote?.setMode(rawValue: m.rawValue) { _, _ in }
    }

    func addRule(_ rule: Rule) {
        guard let data = try? JSONEncoder().encode(rule) else { return }
        remote?.addRule(ruleJSON: data) { _, _ in }
    }

    func removeRule(id: UUID) {
        remote?.removeRule(idString: id.uuidString) { _, _ in }
    }

    func listRules(profile: String = "", completion: @MainActor @escaping ([Rule]) -> Void) {
        remote?.listRules(profile: profile) { data in
            let rules = (try? JSONDecoder().decode([Rule].self, from: data)) ?? []
            Task { @MainActor in completion(rules) }
        }
    }

    func startMonitoring() {
        remote?.startMonitoring { _, _ in }
    }

    func refreshBlocklists() {
        remote?.refreshBlocklists { _, _ in }
    }

    func setEnforcementEnabled(_ enabled: Bool) {
        remote?.setEnforcementEnabled(enabled) { [weak self] ok, message in
            guard !ok else { return }
            Task { @MainActor in
                guard let self else { return }
                self.state?.appendLog(level: "error",
                                      message: "Enforcement change failed: \(message ?? "unknown error")")
                // The helper rolled back, so the UI must not keep claiming
                // enforcement is on.
                self.state?.setEnforcementFlagWithoutApplying(!enabled)
            }
        }
    }

    func installPF() {
        remote?.installPF { _, _ in }
    }

    func uninstallPF() {
        remote?.uninstallPF { _, _ in }
    }
}

final class HelperEventReceiver: NSObject, HelperClientProtocol {
    weak var state: AppState?
    init(state: AppState?) { self.state = state }

    func notifyConnection(connectionJSON: Data) {
        guard let conns = try? JSONDecoder().decode([Connection].self, from: connectionJSON) else { return }
        Task { @MainActor in self.state?.updateConnections(conns) }
    }

    func notifyTraffic(sampleJSON: Data) {
        guard let sample = try? JSONDecoder().decode(TrafficSample.self, from: sampleJSON) else { return }
        Task { @MainActor in self.state?.appendSample(sample) }
    }

    func notifyAlert(connectionJSON: Data, reply: @escaping (Bool, Bool) -> Void) {
        guard let conn = try? JSONDecoder().decode(Connection.self, from: connectionJSON) else { reply(true, false); return }
        Task { @MainActor in self.state?.presentAlert(for: conn, reply: reply) }
    }

    func notifyLog(level: String, message: String) {
        Task { @MainActor in self.state?.appendLog(level: level, message: message) }
    }
}
