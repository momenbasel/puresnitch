import Foundation
import SystemExtensions
import NetworkExtension
import os.log

/// Drives the per-process firewall: activates the embedded Network System
/// Extension, enables the content filter via NEFilterManager, and opens the XPC
/// channel so the extension can prompt the user (reusing the connection-alert
/// UI). Mirrors Apple's "SimpleFirewall" sample.
@MainActor
final class SystemExtensionManager: NSObject, ObservableObject {
    enum Status: Equatable {
        case idle
        case activating
        case needsApproval
        case active
        case unsupported
        case failed(String)
    }

    @Published var status: Status = .idle

    private weak var state: AppState?
    private let extensionIdentifier = AppConstants.bundleIdNetExt
    private let log = OSLog(subsystem: AppConstants.bundleIdGUI, category: "sysext")
    private var bridge: AppCommunicationBridge?
    private var deactivationRequest: OSSystemExtensionRequest?

    init(state: AppState) {
        self.state = state
        super.init()
    }

    private var hasEmbeddedExtension: Bool {
        let dir = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions")
        guard let urls = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else { return false }
        return urls.contains { $0.pathExtension == "systemextension" }
    }

    /// Activate the extension (no-op if this build doesn't embed one).
    func activate() {
        guard hasEmbeddedExtension else {
            status = .unsupported
            return
        }
        status = .activating
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Teardown is sequenced: the filter configuration is removed, not just
    /// disabled, and the extension is deactivated only once that write has
    /// landed, so no "PureSnitch" row outlives the app in network preferences.
    func deactivate() {
        guard hasEmbeddedExtension else { return }
        removeFilterConfiguration { [weak self] in
            guard let self else { return }
            let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: self.extensionIdentifier, queue: .main)
            request.delegate = self
            self.deactivationRequest = request
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    // MARK: - Content filter configuration

    private func enableFilter() {
        let mgr = NEFilterManager.shared()
        mgr.loadFromPreferences { [weak self] loadError in
            DispatchQueue.main.async {
                guard let self else { return }
                if let loadError { self.fail("filter load: \(loadError.localizedDescription)"); return }
                if mgr.providerConfiguration == nil {
                    let cfg = NEFilterProviderConfiguration()
                    cfg.filterSockets = true
                    cfg.filterPackets = false
                    mgr.providerConfiguration = cfg
                    mgr.localizedDescription = "PureSnitch"
                }
                mgr.isEnabled = true
                mgr.saveToPreferences { saveError in
                    DispatchQueue.main.async {
                        if let saveError { self.fail("filter save: \(saveError.localizedDescription)"); return }
                        self.status = .active
                        // Deliberately does NOT touch `helperConnected`: the
                        // content filter and the privileged helper are separate
                        // subsystems, and claiming the helper is up here made
                        // the UI report "connected" while XPC was dead.
                        self.state?.appendLog(level: "info", message: "Per-process firewall active.")
                        self.registerIPC()
                    }
                }
            }
        }
    }

    private func removeFilterConfiguration(completion: @escaping () -> Void) {
        let mgr = NEFilterManager.shared()
        mgr.loadFromPreferences { [weak self] loadError in
            DispatchQueue.main.async {
                if let loadError {
                    self?.state?.appendLog(level: "error",
                                           message: "filter load during teardown: \(loadError.localizedDescription)")
                    completion()
                    return
                }
                // removeFromPreferences errors when nothing is persisted, so a
                // clean teardown would otherwise log a spurious failure.
                guard mgr.providerConfiguration != nil else { completion(); return }
                mgr.isEnabled = false
                mgr.removeFromPreferences { removeError in
                    DispatchQueue.main.async {
                        if let removeError {
                            self?.state?.appendLog(level: "error",
                                                   message: "filter remove: \(removeError.localizedDescription)")
                        }
                        completion()
                    }
                }
            }
        }
    }

    private func registerIPC() {
        guard let state else { return }
        let bridge = AppCommunicationBridge(state: state)
        self.bridge = bridge
        IPCConnection.shared.register(delegate: bridge) { ok in
            DispatchQueue.main.async {
                state.appendLog(level: ok ? "info" : "error",
                                message: ok ? "Connected to network extension." : "Extension IPC unavailable.")
            }
        }
    }

    private func fail(_ message: String) {
        status = .failed(message)
        state?.appendLog(level: "error", message: message)
        os_log("%{public}@", log: log, type: .error, message)
    }
}

extension SystemExtensionManager: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
            if request === self.deactivationRequest {
                self.deactivationRequest = nil
                self.status = .idle
                self.state?.appendLog(level: "info", message: result == .completed
                                      ? "Network extension deactivated."
                                      : "Network extension deactivates after reboot.")
                return
            }
            if result == .completed {
                self.enableFilter()
            } else {
                self.state?.appendLog(level: "info", message: "Network extension finishes after reboot.")
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            if request === self.deactivationRequest {
                self.deactivationRequest = nil
                self.fail("Extension deactivation failed: \(error.localizedDescription)")
                return
            }
            self.fail("Extension activation failed: \(error.localizedDescription)")
        }
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            self.status = .needsApproval
            self.state?.appendLog(level: "info",
                                  message: "Approve PureSnitch in System Settings > Privacy & Security, then it will start filtering.")
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}

/// App-side XPC object the extension calls to ask the user about a paused flow.
/// Bridges into the existing connection-alert UI via AppState.
final class AppCommunicationBridge: NSObject, AppCommunication {
    private weak var state: AppState?
    init(state: AppState) { self.state = state }

    func promptUser(flowJSON: Data, responseHandler: @escaping (Bool, Bool) -> Void) {
        guard let conn = try? JSONDecoder().decode(Connection.self, from: flowJSON) else {
            responseHandler(true, false); return
        }
        Task { @MainActor in
            guard let state = self.state else { responseHandler(true, false); return }
            state.presentAlert(for: conn, reply: responseHandler)
        }
    }
}
