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
    private var pollTimer: Timer?
    private var isRepairing = false
    private var enabledButSilentSince: Date?
    private var connectionEpoch = 0
    private var enforcementRequestGeneration = 0
    private var pendingEnforcementRequestGeneration: Int?
    private var statusRequestGeneration = 0
    private var pendingStatusRequestGeneration: Int?
    private var didLogStatusUnavailable = false
    private var modeRequestGeneration = 0
    private var pendingModeRequestGeneration: Int?
    private var interruptedRecoveryRequestGeneration = 0
    private var pendingInterruptedRecoveryRequestGeneration: Int?
    private var interruptedRecoveryAttemptCount = 0
    private var interruptedRecoveryNextAttemptAt = Date.distantPast
    private var didLogInterruptedRecoveryExhaustion = false
    private var helperShutdownRequestGeneration = 0
    private var legacyFinalizationRequestGeneration = 0
    private var pendingLegacyFinalizationRequestGeneration: Int?
    private var legacyMigrationAttemptVersion: String?
    private var legacyMigrationAttemptCount = 0
    private var didLogLegacyMigrationExhaustion = false
    private var capturedLegacyEnforcementIntent: Bool?
    private var explicitLegacyEnforcementChoice: Bool?
    private var legacyRepairAwaitingFinalization = false
    private var legacyDecisionPromptPresented = false
    private var legacyDecisionDeferred = false
    private var shouldRestoreEnforcementAfterFailedUnregistration = false
    private var helperVersionBeforeUnregistration: String?
    private var helperHadPendingLegacyMigrationBeforeUnregistration = false
    /// Approved but unreachable for long enough that re-registering is worth
    /// offering. Never acted on automatically — see startPolling().
    /// Version string reported by the running daemon, when it answers at all.
    @Published var helperVersion: String?
    @Published var needsRepair = false {
        didSet { state?.helperNeedsRepair = needsRepair }
    }
    weak var state: AppState?

    var keepsEnforcementControlsLocked: Bool {
        isRepairing
            || pendingEnforcementRequestGeneration != nil
            || pendingInterruptedRecoveryRequestGeneration != nil
    }

    var keepsModeControlsLocked: Bool {
        isRepairing || pendingModeRequestGeneration != nil
    }

    private var service: SMAppService? {
        guard #available(macOS 13.0, *) else { return nil }
        return SMAppService.daemon(plistName: "io.moamenbasel.puresnitch.helper.plist")
    }

    private static func isLegacyHelperVersion(_ version: String?) -> Bool {
        version == "0.1.0" || version == "0.2.0"
    }

    private static let maximumLegacyMigrationAttempts = 3
    private static let maximumInterruptedRecoveryAttempts = 3
    private static let statusRequestTimeout: TimeInterval = 6
    private static let interruptedRecoveryTimeout: TimeInterval = 15
    private static let interruptedRecoveryBackoff: [TimeInterval] = [3, 9, 30]
    private func clearLegacyUpgradeState() {
        capturedLegacyEnforcementIntent = nil
        explicitLegacyEnforcementChoice = nil
        legacyRepairAwaitingFinalization = false
        legacyDecisionPromptPresented = false
        legacyDecisionDeferred = false
        legacyMigrationAttemptVersion = nil
        legacyMigrationAttemptCount = 0
        didLogLegacyMigrationExhaustion = false
    }

    private func beginLegacyMigrationAttempt(version: String) -> Bool {
        if legacyMigrationAttemptVersion != version {
            legacyMigrationAttemptVersion = version
            legacyMigrationAttemptCount = 0
            didLogLegacyMigrationExhaustion = false
        }
        guard legacyMigrationAttemptCount < Self.maximumLegacyMigrationAttempts else {
            if !didLogLegacyMigrationExhaustion {
                didLogLegacyMigrationExhaustion = true
                state?.appendLog(
                    level: "error",
                    message: "CRITICAL: legacy firewall migration is still pending after repeated failures. Firewall state is unknown; use Repair Helper to retry."
                )
            }
            needsRepair = true
            return false
        }
        legacyMigrationAttemptCount += 1
        return true
    }

    private func invalidatePendingStatusRequest() {
        statusRequestGeneration &+= 1
        pendingStatusRequestGeneration = nil
    }

    private func markStatusUnavailable(_ message: String?) {
        status = nil
        state?.helperStatusLoaded = false
        state?.pfctlEnabled = false
        state?.dnsProxyEnabled = false
        needsRepair = true
        guard let message, !didLogStatusUnavailable else { return }
        didLogStatusUnavailable = true
        state?.appendLog(level: "error", message: message)
    }

    /// Connection replacement cancels only the in-flight attempt. The durable
    /// helper-owned desired state must be observed again before recovery intent
    /// can be cleared or another privileged mutation can be sent.
    private func cancelInterruptedRecoveryAttemptForConnectionChange() {
        interruptedRecoveryRequestGeneration &+= 1
        pendingInterruptedRecoveryRequestGeneration = nil
    }

    private func resetInterruptedRecoveryRetryBudget() {
        interruptedRecoveryAttemptCount = 0
        interruptedRecoveryNextAttemptAt = .distantPast
        didLogInterruptedRecoveryExhaustion = false
    }

    private func armInterruptedUnregistrationRecovery() {
        shouldRestoreEnforcementAfterFailedUnregistration = true
        resetInterruptedRecoveryRetryBudget()
    }

    /// This is the only non-declaration write that clears interrupted-cleanup
    /// intent. Callers must hold one of the authoritative proofs documented by
    /// the method name: current-version status says desired-off, current-version
    /// status confirms desired-on with both runtimes active, or launchd confirms
    /// that unregister succeeded.
    private func clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution() {
        shouldRestoreEnforcementAfterFailedUnregistration = false
        interruptedRecoveryRequestGeneration &+= 1
        pendingInterruptedRecoveryRequestGeneration = nil
        resetInterruptedRecoveryRetryBudget()
        helperVersionBeforeUnregistration = nil
        helperHadPendingLegacyMigrationBeforeUnregistration = false
        if !isRepairing && pendingEnforcementRequestGeneration == nil {
            state?.enforcementRequestInFlight = false
        }
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
        guard !isRepairing, let service else { return }
        isRepairing = true
        prepareHelperForUnregistration { [weak self] ready in
            guard let self else { return }
            guard ready else {
                self.isRepairing = false
                return
            }
            guard !Self.isLegacyHelperVersion(self.helperVersionBeforeUnregistration),
                  !self.helperHadPendingLegacyMigrationBeforeUnregistration else {
                let version = self.helperVersionBeforeUnregistration ?? "legacy"
                self.state?.appendLog(
                    level: "error",
                    message: "PureSnitch v\(version) has preserved legacy PF state and can only be removed through Repair Helper so a replacement can reconcile it."
                )
                self.recoverRuntimeAfterFailedUnregistration()
                return
            }
            service.unregister { [weak self] error in
                Task { @MainActor in
                    guard let self else { return }
                    if let error {
                        self.state?.appendLog(level: "error", message: "Helper removal failed: \(error.localizedDescription)")
                    }
                    self.refreshInstallState()
                    if error != nil {
                        self.recoverRuntimeAfterFailedUnregistration()
                    } else {
                        self.clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution()
                        self.state?.enforcementRequestInFlight = false
                        self.isRepairing = false
                    }
                }
            }
        }
    }

    /// Re-registers the daemon. After the app bundle is replaced (an update, or
    /// a reinstall over the top) macOS keeps the Background Item approved but
    /// launchd no longer has the job, so `status` reads `.enabled` while
    /// nothing is listening. Unregistering and registering again is Apple's
    /// prescribed repair for exactly that state.
    func repairHelper() {
        guard !isRepairing else { return }
        // An explicit repair action may retry an exhausted interrupted-cleanup
        // recovery, but it still cannot clear the retained intent by itself.
        resetInterruptedRecoveryRetryBudget()
        let retryRequiresRestart = didLogLegacyMigrationExhaustion
        legacyMigrationAttemptVersion = nil
        legacyMigrationAttemptCount = 0
        didLogLegacyMigrationExhaustion = false
        legacyDecisionDeferred = false
        if legacyRepairAwaitingFinalization,
           helperVersion == AppConstants.version,
           !retryRequiresRestart {
            ping()
            return
        }
        guard let service else { return }
        isRepairing = true
        guard connection != nil, helperVersion != nil else {
            replaceUnreachableHelper(using: service)
            return
        }
        prepareHelperForUnregistration { [weak self] ready in
            guard let self else { return }
            guard ready else {
                self.isRepairing = false
                return
            }
            if Self.isLegacyHelperVersion(self.helperVersionBeforeUnregistration) {
                // The old helper is left untouched. The replacement helper's
                // root-owned migration status is the only durable signal that
                // can authorize automatic continuation after this process.
                self.legacyRepairAwaitingFinalization = true
            }
            service.unregister { [weak self] unregisterError in
                Task { @MainActor in
                    guard let self else { return }
                    if let unregisterError {
                        self.state?.appendLog(
                            level: "error",
                            message: "Helper repair stopped because removal failed: \(unregisterError.localizedDescription)"
                        )
                        self.recoverRuntimeAfterFailedUnregistration()
                        return
                    }
                    let replacedLegacyVersion = Self.isLegacyHelperVersion(self.helperVersionBeforeUnregistration)
                        ? self.helperVersionBeforeUnregistration
                        : nil
                    do {
                        guard let replacementService = self.service else {
                            throw NSError(
                                domain: "HelperClient",
                                code: 1,
                                userInfo: [NSLocalizedDescriptionKey: "Helper service is unavailable"]
                            )
                        }
                        try replacementService.register()
                    } catch {
                        let ns = error as NSError
                        self.installState = .failed(ns.localizedFailureReason ?? ns.localizedDescription)
                        if let replacedLegacyVersion {
                            self.state?.appendLog(
                                level: "error",
                                message: "CRITICAL: the v\(replacedLegacyVersion) helper was removed but its replacement could not be registered. Legacy PF cleanup cannot be independently verified; retry Repair Helper before trusting firewall state."
                            )
                        }
                    }
                    self.clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution()
                    self.state?.enforcementRequestInFlight = false
                    self.refreshInstallState()
                    if let replacedLegacyVersion, self.installState != .enabled {
                        self.state?.appendLog(
                            level: "error",
                            message: "CRITICAL: the v\(replacedLegacyVersion) replacement is not enabled yet. Approve or retry Repair Helper before trusting legacy PF cleanup."
                        )
                    }
                    self.isRepairing = false
                    self.reconnectAndPing()
                }
            }
        }
    }

    /// An approved but unreachable helper cannot acknowledge cleanup. Replace
    /// it without mutating PF; the current helper must then report either a
    /// healthy checked reconciliation or root-owned migration-pending state.
    private func replaceUnreachableHelper(using service: SMAppService) {
        legacyRepairAwaitingFinalization = true
        state?.appendLog(
            level: "error",
            message: "Helper is unreachable; preserving existing PF state while installing a replacement for checked reconciliation."
        )
        service.unregister { [weak self] unregisterError in
            Task { @MainActor in
                guard let self else { return }
                if let unregisterError {
                    self.isRepairing = false
                    self.state?.appendLog(
                        level: "error",
                        message: "Helper repair stopped because the unreachable service could not be removed: \(unregisterError.localizedDescription)"
                    )
                    return
                }
                self.clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution()
                do {
                    guard let replacementService = self.service else {
                        throw NSError(
                            domain: "HelperClient",
                            code: 2,
                            userInfo: [NSLocalizedDescriptionKey: "Helper service is unavailable"]
                        )
                    }
                    try replacementService.register()
                } catch {
                    let ns = error as NSError
                    self.installState = .failed(ns.localizedFailureReason ?? ns.localizedDescription)
                    self.state?.appendLog(
                        level: "error",
                        message: "CRITICAL: replacement helper registration failed while preserved PF state remains unresolved: \(ns.localizedDescription)"
                    )
                }
                self.refreshInstallState()
                self.isRepairing = false
                self.reconnectAndPing()
            }
        }
    }

    /// A launchd unregister can terminate the helper immediately. Current
    /// helpers perform checked teardown first; legacy helpers are deliberately
    /// left untouched so the replacement can preserve or reconcile their PF
    /// state without trusting old cleanup acknowledgements.
    private func prepareHelperForUnregistration(completion: @MainActor @escaping (Bool) -> Void) {
        guard state?.enforcementRequestInFlight != true else {
            state?.appendLog(level: "error", message: "Wait for the enforcement change to finish before repairing the helper.")
            completion(false)
            return
        }
        guard pendingModeRequestGeneration == nil else {
            state?.appendLog(level: "error", message: "Wait for the mode change to finish before repairing the helper.")
            completion(false)
            return
        }
        guard let connection else {
            state?.appendLog(level: "error", message: "Helper removal stopped: cannot confirm that firewall enforcement is inactive.")
            completion(false)
            return
        }
        let connectionEpoch = self.connectionEpoch
        helperVersionBeforeUnregistration = nil
        helperHadPendingLegacyMigrationBeforeUnregistration = false

        state?.enforcementRequestInFlight = true
        invalidatePendingStatusRequest()
        helperShutdownRequestGeneration &+= 1
        let generation = helperShutdownRequestGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            self?.finishHelperShutdownPreparation(
                generation: generation,
                connection: connection,
                connectionEpoch: connectionEpoch,
                ready: false,
                message: "Helper removal stopped: timed out while disabling firewall enforcement.",
                completion: completion
            )
        }

        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self] error in
            Task { @MainActor in
                self?.finishHelperShutdownPreparation(
                    generation: generation,
                    connection: connection,
                    connectionEpoch: connectionEpoch,
                    ready: false,
                    message: "Helper removal stopped: could not verify firewall cleanup (\(error.localizedDescription)).",
                    completion: completion
                )
            }
        } as? HelperProtocol
        guard let proxy else {
            finishHelperShutdownPreparation(
                generation: generation,
                connection: connection,
                connectionEpoch: connectionEpoch,
                ready: false,
                message: "Helper removal stopped: XPC proxy unavailable.",
                completion: completion
            )
            return
        }

        proxy.getStatus { [weak self] data in
            let status = try? JSONDecoder().decode(HelperStatus.self, from: data)
            Task { @MainActor in
                guard let self,
                      generation == self.helperShutdownRequestGeneration,
                      connectionEpoch == self.connectionEpoch,
                      self.connection === connection else { return }
                guard let status else {
                    self.finishHelperShutdownPreparation(
                        generation: generation,
                        connection: connection,
                        connectionEpoch: connectionEpoch,
                        ready: false,
                        message: "Helper removal stopped: could not decode helper status.",
                        completion: completion
                    )
                    return
                }

                let runtimeWasActive = status.pfctlActive || status.dnsProxyActive
                self.helperVersionBeforeUnregistration = status.version
                self.helperHadPendingLegacyMigrationBeforeUnregistration = status.legacyPFMigrationPending
                if status.version == AppConstants.version && !status.enforcementDesired {
                    self.clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution()
                    // The shutdown preparation still owns the UI lock.
                    self.state?.enforcementRequestInFlight = true
                }
                if status.legacyPFMigrationPending {
                    self.finishHelperShutdownPreparation(
                        generation: generation,
                        connection: connection,
                        connectionEpoch: connectionEpoch,
                        ready: true,
                        message: nil,
                        completion: completion
                    )
                    return
                }
                if status.version == AppConstants.version {
                    if status.enforcementDesired && runtimeWasActive {
                        self.armInterruptedUnregistrationRecovery()
                    }
                } else if Self.isLegacyHelperVersion(status.version) {
                    // Legacy DNS and net monitoring are process-local and can
                    // remain running until launchd terminates the old helper.
                    // Only observed root-owned runtime state is safe to carry
                    // automatically. A false legacy status can be stale after
                    // restart, so it is unknown rather than an instruction to
                    // disable. UserDefaults never authorizes a root mutation.
                    if status.pfctlActive {
                        self.capturedLegacyEnforcementIntent = true
                    }
                }

                if Self.isLegacyHelperVersion(status.version) {
                    // Preserve legacy PF fail-closed until the replacement
                    // helper performs checked reconciliation. Old uninstallPF
                    // acknowledgements cannot be trusted and reload rollback
                    // has unavoidable late-callback races.
                    self.finishHelperShutdownPreparation(
                        generation: generation,
                        connection: connection,
                        connectionEpoch: connectionEpoch,
                        ready: true,
                        message: nil,
                        completion: completion
                    )
                    return
                }

                if !runtimeWasActive {
                    self.finishHelperShutdownPreparation(
                        generation: generation,
                        connection: connection,
                        connectionEpoch: connectionEpoch,
                        ready: true,
                        message: nil,
                        completion: completion
                    )
                    return
                }

                guard status.version == AppConstants.version || status.version == "0.2.0" else {
                    self.finishHelperShutdownPreparation(
                        generation: generation,
                        connection: connection,
                        connectionEpoch: connectionEpoch,
                        ready: false,
                        message: "Helper removal stopped: unsupported helper version \(status.version) is still enforcing traffic.",
                        completion: completion
                    )
                    return
                }

                let cleanupReply: (Bool, String?) -> Void = { [weak self] ok, message in
                    Task { @MainActor in
                        self?.finishHelperShutdownPreparation(
                            generation: generation,
                            connection: connection,
                            connectionEpoch: connectionEpoch,
                            ready: ok,
                            message: ok ? nil : "Helper removal stopped: \(message ?? "firewall cleanup failed").",
                            completion: completion
                        )
                    }
                }
                proxy.prepareForUnregistration(reply: cleanupReply)
            }
        }
    }

    private func finishHelperShutdownPreparation(
        generation: Int,
        connection expectedConnection: NSXPCConnection,
        connectionEpoch expectedConnectionEpoch: Int,
        ready: Bool,
        message: String?,
        completion: @MainActor @escaping (Bool) -> Void
    ) {
        guard generation == helperShutdownRequestGeneration else { return }
        helperShutdownRequestGeneration &+= 1
        let isCurrentConnection = expectedConnectionEpoch == connectionEpoch && connection === expectedConnection
        let preparationSucceeded = ready && isCurrentConnection
        let shouldReconcileInterruptedCleanup = !preparationSucceeded
            && shouldRestoreEnforcementAfterFailedUnregistration
        if preparationSucceeded {
            if !Self.isLegacyHelperVersion(helperVersionBeforeUnregistration)
                && !helperHadPendingLegacyMigrationBeforeUnregistration {
                state?.pfctlEnabled = false
                state?.dnsProxyEnabled = false
            }
        } else {
            if !shouldReconcileInterruptedCleanup {
                helperVersionBeforeUnregistration = nil
            }
            state?.enforcementRequestInFlight = false
            let failure = isCurrentConnection
                ? (message ?? "Helper removal stopped: firewall cleanup was not confirmed.")
                : "Helper removal stopped: the helper connection changed before firewall cleanup was confirmed."
            state?.appendLog(level: "error", message: failure)
            if shouldReconcileInterruptedCleanup {
                needsRepair = true
            }
        }
        completion(preparationSucceeded)
        if shouldReconcileInterruptedCleanup {
            // The caller releases isRepairing after completion returns. Re-read
            // authenticated helper state on the next main-queue turn; never
            // infer that a lost cleanup reply means enforcement is off.
            DispatchQueue.main.async { [weak self] in
                self?.refreshStatus()
            }
        }
    }

    private func recoverRuntimeAfterFailedUnregistration() {
        isRepairing = false
        state?.enforcementRequestInFlight = false
        if shouldRestoreEnforcementAfterFailedUnregistration {
            needsRepair = true
            state?.appendLog(
                level: "error",
                message: "Helper removal failed after cleanup began; authenticated helper status will reconcile the retained enforcement intent."
            )
            refreshStatus()
        } else {
            helperVersionBeforeUnregistration = nil
            helperHadPendingLegacyMigrationBeforeUnregistration = false
            refreshStatus()
        }
    }

    /// A root-owned helper status is the only durable migration authority.
    /// In-memory intent captured from a live legacy helper can continue the
    /// same repair session; after an app restart, migration-pending state must
    /// be resolved by an explicit user choice.
    private func inspectCurrentHelperForLegacyUpgrade(
        on connection: NSXPCConnection,
        connectionEpoch: Int
    ) {
        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self] error in
            Task { @MainActor in
                guard let self,
                      connectionEpoch == self.connectionEpoch,
                      self.connection === connection else { return }
                self.setConnected(false)
                self.needsRepair = true
                self.state?.appendLog(
                    level: "error",
                    message: "CRITICAL: current helper migration status is unavailable: \(error.localizedDescription)"
                )
            }
        } as? HelperProtocol
        guard let proxy else {
            setConnected(false)
            needsRepair = true
            return
        }

        proxy.getStatus { [weak self] data in
            let helperStatus = try? JSONDecoder().decode(HelperStatus.self, from: data)
            Task { @MainActor in
                guard let self,
                      connectionEpoch == self.connectionEpoch,
                      self.connection === connection else { return }
                guard let helperStatus,
                      helperStatus.version == AppConstants.version else {
                    self.setConnected(false)
                    self.needsRepair = true
                    self.state?.appendLog(
                        level: "error",
                        message: "CRITICAL: replacement helper status could not be authenticated."
                    )
                    return
                }
                self.acceptAuthenticatedCurrentStatus(
                    helperStatus,
                    on: connection,
                    connectionEpoch: connectionEpoch
                )

                if helperStatus.legacyPFMigrationPending {
                    self.legacyRepairAwaitingFinalization = true
                    self.needsRepair = true
                    // A prior on/off intent says nothing about whether replacing
                    // legacy v0.2 rules with the narrower current ruleset is
                    // acceptable. Only a choice made in this signed-app prompt
                    // authorizes reconciliation; an in-memory choice may retry
                    // the same operation after a lost reply.
                    if let explicitChoice = self.explicitLegacyEnforcementChoice {
                        self.finalizeLegacyUpgrade(
                            enabled: explicitChoice,
                            initialStatus: helperStatus,
                            proxy: proxy,
                            connection: connection,
                            connectionEpoch: connectionEpoch
                        )
                    } else if !self.legacyDecisionDeferred {
                        self.promptForLegacyEnforcementDecision(
                            initialStatus: helperStatus,
                            proxy: proxy,
                            connection: connection,
                            connectionEpoch: connectionEpoch
                        )
                    } else {
                        self.setConnected(false)
                    }
                    return
                }

                if self.legacyRepairAwaitingFinalization {
                    guard helperStatus.legacyPFReconciliationSucceeded else {
                        self.setConnected(false)
                        self.needsRepair = true
                        self.state?.appendLog(
                            level: "error",
                            message: "CRITICAL: replacement helper did not confirm checked legacy PF reconciliation."
                        )
                        return
                    }
                    if self.explicitLegacyEnforcementChoice == true,
                       !(helperStatus.enforcementDesired
                            && helperStatus.pfctlActive
                            && helperStatus.dnsProxyActive) {
                        if helperStatus.activeRules == 0 {
                            if !self.legacyDecisionDeferred {
                                self.promptForLegacyEnforcementDecision(
                                    initialStatus: helperStatus,
                                    proxy: proxy,
                                    connection: connection,
                                    connectionEpoch: connectionEpoch
                                )
                            } else {
                                self.setConnected(false)
                            }
                        } else {
                            self.finalizeLegacyUpgrade(
                                enabled: true,
                                initialStatus: helperStatus,
                                proxy: proxy,
                                connection: connection,
                                connectionEpoch: connectionEpoch
                            )
                        }
                        return
                    }
                    self.clearLegacyUpgradeState()
                }
                self.setConnected(true)
                self.acceptAuthenticatedCurrentStatus(
                    helperStatus,
                    on: connection,
                    connectionEpoch: connectionEpoch
                )
            }
        }
    }

    private func promptForLegacyEnforcementDecision(
        initialStatus: HelperStatus,
        proxy: HelperProtocol,
        connection: NSXPCConnection,
        connectionEpoch: Int
    ) {
        guard !legacyDecisionPromptPresented else { return }
        legacyDecisionPromptPresented = true
        isRepairing = true
        setConnected(false)

        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Finish the legacy firewall migration"
        let hasCurrentRules = initialStatus.activeRules > 0
        let priorIntentWasOn = capturedLegacyEnforcementIntent == true
            || initialStatus.enforcementDesired
        if hasCurrentRules {
            alert.informativeText = "PureSnitch found preserved legacy firewall state\(priorIntentWasOn ? " and a previous request to keep enforcement on" : ""), but replacing its rules requires a new explicit choice. Decide Later is the only choice that preserves every legacy rule unchanged. Keep On replaces them with the current v0.2.1 rule store; non-default, allow, process-only, domain-only, disabled, expired, or otherwise non-renderable rules will not survive as host-wide PF rules. Turn Off removes the legacy firewall state."
        } else {
            alert.informativeText = "PureSnitch found preserved legacy firewall state, but the current v0.2.1 rule store is empty. Homebrew recovery snapshots are not imported automatically because tap files are user-writable. Decide Later is the only choice that preserves the legacy firewall rules unchanged. Keep On is unavailable because it would replace them with an empty ruleset; Turn Off removes them."
        }
        // Make the non-mutating choice the default. Pressing Return or closing
        // an unexpected upgrade prompt must preserve the legacy firewall.
        alert.addButton(withTitle: "Decide Later")
        let keepOnButton = alert.addButton(withTitle: "Keep Enforcement On with Current Rules")
        keepOnButton.isEnabled = hasCurrentRules
        alert.addButton(withTitle: "Turn Enforcement Off")
        let response = alert.runModal()

        legacyDecisionPromptPresented = false
        isRepairing = false
        guard connectionEpoch == self.connectionEpoch,
              self.connection === connection else { return }
        switch response {
        case .alertFirstButtonReturn:
            legacyDecisionDeferred = true
            needsRepair = true
            state?.appendLog(
                level: "error",
                message: "CRITICAL: legacy firewall migration is awaiting your enforcement choice; preserved PF state was left unchanged."
            )
            return
        case .alertSecondButtonReturn:
            guard hasCurrentRules else {
                legacyDecisionDeferred = true
                needsRepair = true
                state?.appendLog(
                    level: "error",
                    message: "CRITICAL: Keep On was refused because the current rule store is empty; preserved legacy PF state was left unchanged."
                )
                return
            }
            capturedLegacyEnforcementIntent = true
            explicitLegacyEnforcementChoice = true
        case .alertThirdButtonReturn:
            capturedLegacyEnforcementIntent = false
            explicitLegacyEnforcementChoice = false
        default:
            legacyDecisionDeferred = true
            needsRepair = true
            state?.appendLog(
                level: "error",
                message: "CRITICAL: legacy firewall migration is awaiting your enforcement choice; preserved PF state was left unchanged."
            )
            return
        }
        finalizeLegacyUpgrade(
            enabled: capturedLegacyEnforcementIntent == true,
            initialStatus: initialStatus,
            proxy: proxy,
            connection: connection,
            connectionEpoch: connectionEpoch
        )
    }

    private func finalizeLegacyUpgrade(
        enabled: Bool,
        initialStatus: HelperStatus,
        proxy: HelperProtocol,
        connection: NSXPCConnection,
        connectionEpoch: Int
    ) {
        guard initialStatus.legacyPFMigrationPending
                || initialStatus.legacyPFReconciliationSucceeded else {
            setConnected(false)
            needsRepair = true
            state?.appendLog(
                level: "error",
                message: "CRITICAL: replacement helper has not reported a safe legacy PF migration state."
            )
            return
        }
        guard !enabled || initialStatus.activeRules > 0 else {
            legacyDecisionDeferred = true
            setConnected(false)
            needsRepair = true
            state?.appendLog(
                level: "error",
                message: "CRITICAL: legacy firewall migration was refused because enabling an empty current rule store would discard preserved legacy PF rules."
            )
            return
        }
        guard explicitLegacyEnforcementChoice == enabled else {
            legacyDecisionDeferred = true
            setConnected(false)
            needsRepair = true
            state?.appendLog(
                level: "error",
                message: "CRITICAL: legacy firewall reconciliation requires a new explicit signed-app ruleset choice. Preserved legacy PF state was left unchanged."
            )
            return
        }
        guard pendingLegacyFinalizationRequestGeneration == nil else { return }
        guard beginLegacyMigrationAttempt(version: AppConstants.version) else {
            setConnected(false)
            needsRepair = true
            return
        }

        legacyRepairAwaitingFinalization = true
        legacyFinalizationRequestGeneration &+= 1
        let generation = legacyFinalizationRequestGeneration
        pendingLegacyFinalizationRequestGeneration = generation
        isRepairing = true
        needsRepair = true
        state?.enforcementRequestInFlight = true
        setConnected(false)

        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            self?.finishLegacyUpgradeFinalization(
                generation: generation,
                connection: connection,
                connectionEpoch: connectionEpoch,
                enabled: enabled,
                ok: false,
                message: "checked replacement-helper reconciliation timed out"
            )
        }

        proxy.setEnforcementEnabled(enabled) { [weak self] ok, message in
            Task { @MainActor in
                guard let self,
                      self.pendingLegacyFinalizationRequestGeneration == generation,
                      connectionEpoch == self.connectionEpoch,
                      self.connection === connection else { return }
                guard ok else {
                    self.finishLegacyUpgradeFinalization(
                        generation: generation,
                        connection: connection,
                        connectionEpoch: connectionEpoch,
                        enabled: enabled,
                        ok: false,
                        message: message ?? "replacement helper did not confirm reconciliation"
                    )
                    return
                }

                proxy.getStatus { [weak self] statusData in
                    let confirmedStatus = try? JSONDecoder().decode(
                        HelperStatus.self,
                        from: statusData
                    )
                    Task { @MainActor in
                        guard let self,
                              self.pendingLegacyFinalizationRequestGeneration == generation,
                              connectionEpoch == self.connectionEpoch,
                              self.connection === connection else { return }
                        let runtimeMatches = enabled
                            ? (confirmedStatus?.pfctlActive == true
                                && confirmedStatus?.dnsProxyActive == true)
                            : (confirmedStatus?.pfctlActive == false
                                && confirmedStatus?.dnsProxyActive == false)
                        let reconciled = confirmedStatus?.version == AppConstants.version
                            && confirmedStatus?.legacyPFMigrationPending == false
                            && confirmedStatus?.legacyPFReconciliationSucceeded == true
                            && confirmedStatus?.enforcementDesired == enabled
                            && runtimeMatches
                        self.status = confirmedStatus
                        self.finishLegacyUpgradeFinalization(
                            generation: generation,
                            connection: connection,
                            connectionEpoch: connectionEpoch,
                            enabled: enabled,
                            ok: reconciled,
                            message: reconciled
                                ? nil
                                : "replacement helper status did not confirm the requested legacy PF state"
                        )
                    }
                }
            }
        }
    }

    private func finishLegacyUpgradeFinalization(
        generation: Int,
        connection expectedConnection: NSXPCConnection,
        connectionEpoch expectedConnectionEpoch: Int,
        enabled: Bool,
        ok: Bool,
        message: String?
    ) {
        guard pendingLegacyFinalizationRequestGeneration == generation else { return }
        pendingLegacyFinalizationRequestGeneration = nil
        legacyFinalizationRequestGeneration &+= 1
        isRepairing = false
        state?.enforcementRequestInFlight = false

        let isCurrentConnection = expectedConnectionEpoch == connectionEpoch
            && connection === expectedConnection
        guard ok && isCurrentConnection else {
            setConnected(false)
            needsRepair = true
            state?.appendLog(
                level: "error",
                message: "CRITICAL: legacy firewall migration is still pending; \(message ?? "checked reconciliation failed"). Firewall state is unknown and will be retried."
            )
            return
        }

        clearLegacyUpgradeState()
        clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution()
        state?.pfctlEnabled = enabled
        state?.dnsProxyEnabled = enabled
        needsRepair = false
        state?.appendLog(
            level: "info",
            message: enabled
                ? "Legacy firewall enforcement was migrated and verified by the current helper."
                : "Legacy firewall cleanup was verified by the current helper; enforcement remains off."
        )
        setConnected(true)
        refreshStatus(on: expectedConnection, connectionEpoch: expectedConnectionEpoch)
    }

    func connect() {
        replaceConnection()
        ping()
        startPolling()
    }

    /// Replacing an XPC connection starts a new policy epoch. Every callback
    /// captures this generation so a late reply from an invalidated connection
    /// cannot change connectivity, status, rules, or alert state.
    private func replaceConnection() {
        setConnected(false)
        helperVersion = nil
        connectionEpoch &+= 1
        enforcementRequestGeneration &+= 1
        pendingEnforcementRequestGeneration = nil
        invalidatePendingStatusRequest()
        modeRequestGeneration &+= 1
        pendingModeRequestGeneration = nil
        cancelInterruptedRecoveryAttemptForConnectionChange()
        state?.enforcementRequestInFlight = false
        state?.modeRequestInFlight = false
        markStatusUnavailable(nil)
        state?.beginHelperConnectionEpoch()

        let epoch = connectionEpoch
        let oldConnection = connection
        let conn = NSXPCConnection(machServiceName: AppConstants.xpcMachServiceName, options: [.privileged])
        conn.remoteObjectInterface = HelperBridge.remoteInterface()
        conn.exportedInterface = HelperBridge.exportedInterface()
        conn.exportedObject = HelperEventReceiver(state: state, client: self, connectionEpoch: epoch)
        conn.invalidationHandler = { [weak self, weak conn] in
            Task { @MainActor in
                guard let self, let conn else { return }
                self.markConnectionUnavailable(conn, connectionEpoch: epoch)
            }
        }
        conn.interruptionHandler = { [weak self, weak conn] in
            Task { @MainActor in
                guard let self, let conn else { return }
                self.markConnectionUnavailable(conn, connectionEpoch: epoch)
            }
        }
        connection = conn
        conn.resume()
        oldConnection?.invalidate()
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
                if self.legacyDecisionDeferred {
                    // Decide Later deliberately keeps privileged controls
                    // disconnected. Retain the existing authenticated XPC
                    // connection without churning it every poll; Repair Helper
                    // resets deferral and reuses it to present the choice again.
                    self.enabledButSilentSince = nil
                    self.needsRepair = true
                    return
                }
                guard !self.connected else {
                    self.enabledButSilentSince = nil
                    self.refreshStatus()
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
                    if self.shouldRestoreEnforcementAfterFailedUnregistration
                        || self.legacyRepairAwaitingFinalization {
                        self.needsRepair = true
                    }
                    return
                }
                let since = self.enabledButSilentSince ?? Date()
                self.enabledButSilentSince = since
                self.needsRepair = self.shouldRestoreEnforcementAfterFailedUnregistration
                    || self.legacyRepairAwaitingFinalization
                    || Date().timeIntervalSince(since) > 20
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        pollTimer = timer
    }

    private func reconnectAndPing() {
        // A connection made before the daemon existed stays invalid forever, so
        // rebuild it rather than pinging a dead proxy.
        replaceConnection()
        ping()
    }

    var remote: HelperProtocol? {
        connection?.remoteObjectProxyWithErrorHandler { _ in } as? HelperProtocol
    }

    fileprivate func isCurrentConnectionEpoch(_ epoch: Int) -> Bool {
        epoch == connectionEpoch && connected
    }

    private func markConnectionUnavailable(_ expectedConnection: NSXPCConnection, connectionEpoch expectedEpoch: Int) {
        guard expectedEpoch == connectionEpoch, connection === expectedConnection else { return }
        connection = nil
        helperVersion = nil
        connectionEpoch &+= 1
        enforcementRequestGeneration &+= 1
        pendingEnforcementRequestGeneration = nil
        invalidatePendingStatusRequest()
        modeRequestGeneration &+= 1
        pendingModeRequestGeneration = nil
        cancelInterruptedRecoveryAttemptForConnectionChange()
        state?.enforcementRequestInFlight = false
        state?.modeRequestInFlight = false
        markStatusUnavailable(nil)
        state?.beginHelperConnectionEpoch()
        setConnected(false)
        expectedConnection.invalidate()
    }

    private func setConnected(_ value: Bool) {
        let wasConnected = connected
        connected = value
        state?.helperConnected = value
        guard value, !wasConnected else { return }
        // Every fresh connection re-runs monitoring/rule bootstrap. Runtime
        // enforcement is restored from helper-owned state, never pushed from
        // a per-user GUI preference.
        state?.bootstrap()
    }

    func ping() {
        guard !isRepairing else { return }
        guard let connection else {
            setConnected(false)
            return
        }
        let connectionEpoch = self.connectionEpoch
        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self, weak connection] _ in
            Task { @MainActor in
                guard let self, let connection else { return }
                self.markConnectionUnavailable(connection, connectionEpoch: connectionEpoch)
            }
        } as? HelperProtocol
        guard let proxy else {
            setConnected(false)
            return
        }

        proxy.getVersion { [weak self, weak connection] version in
            Task { @MainActor in
                guard let self, let connection,
                      connectionEpoch == self.connectionEpoch,
                      self.connection === connection else { return }
                guard !version.isEmpty else {
                    self.markConnectionUnavailable(connection, connectionEpoch: connectionEpoch)
                    return
                }
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
                self.inspectCurrentHelperForLegacyUpgrade(
                    on: connection,
                    connectionEpoch: connectionEpoch
                )
            }
        }
    }

    private func refreshStatus() {
        guard connected,
              !isRepairing,
              helperVersion == AppConstants.version,
              pendingEnforcementRequestGeneration == nil,
              pendingModeRequestGeneration == nil,
              pendingInterruptedRecoveryRequestGeneration == nil,
              pendingLegacyFinalizationRequestGeneration == nil else { return }
        guard let connection else { return }
        refreshStatus(on: connection, connectionEpoch: connectionEpoch)
    }

    private func refreshStatus(on connection: NSXPCConnection, connectionEpoch: Int) {
        guard connected,
              !isRepairing,
              helperVersion == AppConstants.version,
              connectionEpoch == self.connectionEpoch,
              self.connection === connection,
              pendingEnforcementRequestGeneration == nil,
              pendingModeRequestGeneration == nil,
              pendingInterruptedRecoveryRequestGeneration == nil,
              pendingLegacyFinalizationRequestGeneration == nil,
              pendingStatusRequestGeneration == nil else { return }

        statusRequestGeneration &+= 1
        let generation = statusRequestGeneration
        pendingStatusRequestGeneration = generation
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.statusRequestTimeout) { [weak self, weak connection] in
            guard let self, let connection else { return }
            self.finishStatusRequest(
                generation: generation,
                connection: connection,
                connectionEpoch: connectionEpoch,
                helperStatus: nil,
                failureMessage: "Helper status timed out; runtime state is unavailable.",
                invalidateConnection: false
            )
        }

        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self, weak connection] error in
            Task { @MainActor in
                guard let self, let connection else { return }
                self.finishStatusRequest(
                    generation: generation,
                    connection: connection,
                    connectionEpoch: connectionEpoch,
                    helperStatus: nil,
                    failureMessage: "Helper status failed: \(error.localizedDescription)",
                    invalidateConnection: true
                )
            }
        } as? HelperProtocol
        guard let proxy else {
            finishStatusRequest(
                generation: generation,
                connection: connection,
                connectionEpoch: connectionEpoch,
                helperStatus: nil,
                failureMessage: "Helper status proxy is unavailable.",
                invalidateConnection: true
            )
            return
        }
        proxy.getStatus { [weak self, weak connection] data in
            let helperStatus = try? JSONDecoder().decode(HelperStatus.self, from: data)
            Task { @MainActor in
                guard let self, let connection else { return }
                let currentVersionStatus = helperStatus?.version == AppConstants.version
                    ? helperStatus
                    : nil
                let failure: String?
                if helperStatus == nil {
                    failure = "Helper returned an unreadable status; runtime state is unavailable."
                } else if currentVersionStatus == nil {
                    failure = "Helper status version could not be authenticated; repair is required."
                } else {
                    failure = nil
                }
                self.finishStatusRequest(
                    generation: generation,
                    connection: connection,
                    connectionEpoch: connectionEpoch,
                    helperStatus: currentVersionStatus,
                    failureMessage: failure,
                    invalidateConnection: helperStatus != nil && currentVersionStatus == nil
                )
            }
        }
    }

    private func finishStatusRequest(
        generation: Int,
        connection expectedConnection: NSXPCConnection,
        connectionEpoch expectedConnectionEpoch: Int,
        helperStatus: HelperStatus?,
        failureMessage: String?,
        invalidateConnection: Bool
    ) {
        guard pendingStatusRequestGeneration == generation,
              expectedConnectionEpoch == connectionEpoch,
              connection === expectedConnection else { return }
        pendingStatusRequestGeneration = nil

        guard let helperStatus else {
            markStatusUnavailable(failureMessage)
            if invalidateConnection {
                markConnectionUnavailable(
                    expectedConnection,
                    connectionEpoch: expectedConnectionEpoch
                )
            }
            return
        }
        acceptAuthenticatedCurrentStatus(
            helperStatus,
            on: expectedConnection,
            connectionEpoch: expectedConnectionEpoch
        )
    }

    private func acceptAuthenticatedCurrentStatus(
        _ helperStatus: HelperStatus,
        on expectedConnection: NSXPCConnection,
        connectionEpoch expectedConnectionEpoch: Int
    ) {
        guard helperStatus.version == AppConstants.version,
              expectedConnectionEpoch == connectionEpoch,
              connection === expectedConnection else { return }

        let runtimeMatchesDesired = helperStatus.enforcementDesired
            ? (helperStatus.pfctlActive && helperStatus.dnsProxyActive)
            : (!helperStatus.pfctlActive && !helperStatus.dnsProxyActive)

        // Root-owned current-helper desired state is sufficient authority to
        // repair its own degraded runtime. This also survives a GUI crash after
        // prepareForUnregistration: the next signed GUI re-arms recovery from
        // authenticated status instead of relying on process-local memory.
        if helperStatus.enforcementDesired
            && !runtimeMatchesDesired
            && !helperStatus.legacyPFMigrationPending
            && !shouldRestoreEnforcementAfterFailedUnregistration {
            armInterruptedUnregistrationRecovery()
        }
        let mayRecoverInterruptedCleanup = shouldRestoreEnforcementAfterFailedUnregistration
            && helperStatus.enforcementDesired
            && !runtimeMatchesDesired
            && !helperStatus.legacyPFMigrationPending

        if !helperStatus.enforcementDesired
            || (helperStatus.pfctlActive && helperStatus.dnsProxyActive) {
            clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution()
        }

        didLogStatusUnavailable = false
        status = helperStatus
        needsRepair = !runtimeMatchesDesired
            || helperStatus.legacyPFMigrationPending
            || !helperStatus.legacyPFReconciliationSucceeded
            || legacyRepairAwaitingFinalization

        if mayRecoverInterruptedCleanup {
            beginInterruptedUnregistrationRecovery(
                after: helperStatus,
                on: expectedConnection,
                connectionEpoch: expectedConnectionEpoch
            )
        }
    }

    private func beginInterruptedUnregistrationRecovery(
        after helperStatus: HelperStatus,
        on expectedConnection: NSXPCConnection,
        connectionEpoch expectedConnectionEpoch: Int
    ) {
        guard shouldRestoreEnforcementAfterFailedUnregistration,
              helperStatus.version == AppConstants.version,
              helperStatus.enforcementDesired,
              !helperStatus.legacyPFMigrationPending,
              !(helperStatus.pfctlActive && helperStatus.dnsProxyActive),
              connected,
              !isRepairing,
              expectedConnectionEpoch == connectionEpoch,
              connection === expectedConnection,
              pendingEnforcementRequestGeneration == nil,
              pendingModeRequestGeneration == nil,
              pendingInterruptedRecoveryRequestGeneration == nil,
              pendingLegacyFinalizationRequestGeneration == nil else { return }

        guard interruptedRecoveryAttemptCount < Self.maximumInterruptedRecoveryAttempts else {
            if !didLogInterruptedRecoveryExhaustion {
                didLogInterruptedRecoveryExhaustion = true
                state?.appendLog(
                    level: "error",
                    message: "CRITICAL: enforcement remained degraded after repeated interrupted-cleanup recovery attempts. Use Repair Helper before trusting firewall state."
                )
            }
            needsRepair = true
            return
        }
        guard Date() >= interruptedRecoveryNextAttemptAt else { return }

        interruptedRecoveryAttemptCount += 1
        let backoffIndex = min(
            interruptedRecoveryAttemptCount - 1,
            Self.interruptedRecoveryBackoff.count - 1
        )
        interruptedRecoveryNextAttemptAt = Date().addingTimeInterval(
            Self.interruptedRecoveryBackoff[backoffIndex]
        )
        interruptedRecoveryRequestGeneration &+= 1
        let generation = interruptedRecoveryRequestGeneration
        pendingInterruptedRecoveryRequestGeneration = generation
        state?.enforcementRequestInFlight = true
        needsRepair = true

        DispatchQueue.main.asyncAfter(deadline: .now() + Self.interruptedRecoveryTimeout) { [weak self, weak expectedConnection] in
            guard let self, let expectedConnection else { return }
            self.finishInterruptedUnregistrationRecovery(
                generation: generation,
                connection: expectedConnection,
                connectionEpoch: expectedConnectionEpoch,
                ok: false,
                message: "Interrupted-cleanup enforcement recovery timed out."
            )
        }

        let proxy = expectedConnection.remoteObjectProxyWithErrorHandler { [weak self, weak expectedConnection] error in
            Task { @MainActor in
                guard let self, let expectedConnection else { return }
                self.finishInterruptedUnregistrationRecovery(
                    generation: generation,
                    connection: expectedConnection,
                    connectionEpoch: expectedConnectionEpoch,
                    ok: false,
                    message: "Interrupted-cleanup recovery failed: \(error.localizedDescription)"
                )
                self.markConnectionUnavailable(
                    expectedConnection,
                    connectionEpoch: expectedConnectionEpoch
                )
            }
        } as? HelperProtocol
        guard let proxy else {
            finishInterruptedUnregistrationRecovery(
                generation: generation,
                connection: expectedConnection,
                connectionEpoch: expectedConnectionEpoch,
                ok: false,
                message: "Interrupted-cleanup recovery proxy is unavailable."
            )
            return
        }
        proxy.setEnforcementEnabled(true) { [weak self, weak expectedConnection] ok, message in
            Task { @MainActor in
                guard let self, let expectedConnection else { return }
                self.finishInterruptedUnregistrationRecovery(
                    generation: generation,
                    connection: expectedConnection,
                    connectionEpoch: expectedConnectionEpoch,
                    ok: ok,
                    message: ok ? nil : "Interrupted-cleanup recovery failed: \(message ?? "unknown error")"
                )
            }
        }
    }

    private func finishInterruptedUnregistrationRecovery(
        generation: Int,
        connection expectedConnection: NSXPCConnection,
        connectionEpoch expectedConnectionEpoch: Int,
        ok: Bool,
        message: String?
    ) {
        guard pendingInterruptedRecoveryRequestGeneration == generation,
              expectedConnectionEpoch == connectionEpoch,
              connection === expectedConnection else { return }
        pendingInterruptedRecoveryRequestGeneration = nil
        state?.enforcementRequestInFlight = pendingEnforcementRequestGeneration != nil
        if !ok {
            needsRepair = true
            state?.appendLog(
                level: "error",
                message: message ?? "Interrupted-cleanup enforcement recovery failed."
            )
        }
        // A mutation acknowledgement is not runtime proof. Only the following
        // authenticated status may clear retained recovery intent.
        refreshStatus()
    }

    func setMode(_ m: AppMode) {
        modeRequestGeneration &+= 1
        invalidatePendingStatusRequest()
        let generation = modeRequestGeneration
        pendingModeRequestGeneration = generation

        guard let connection else {
            finishModeRequest(
                generation: generation,
                connectionEpoch: connectionEpoch,
                ok: false,
                message: "Mode change never reached the helper: no active XPC connection",
                refreshIfAlreadySettled: false
            )
            return
        }
        let connectionEpoch = self.connectionEpoch
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            self?.finishModeRequest(
                generation: generation,
                connectionEpoch: connectionEpoch,
                ok: false,
                message: "Mode change timed out; helper state is being reconciled",
                refreshIfAlreadySettled: false
            )
        }

        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self] error in
            Task { @MainActor in
                self?.finishModeRequest(
                    generation: generation,
                    connectionEpoch: connectionEpoch,
                    ok: false,
                    message: "Mode change never reached the helper: \(error.localizedDescription)",
                    refreshIfAlreadySettled: true
                )
            }
        } as? HelperProtocol
        guard let proxy else {
            finishModeRequest(
                generation: generation,
                connectionEpoch: connectionEpoch,
                ok: false,
                message: "Mode change never reached the helper: XPC proxy unavailable",
                refreshIfAlreadySettled: false
            )
            return
        }
        proxy.setMode(rawValue: m.rawValue) { [weak self] ok, message in
            Task { @MainActor in
                self?.finishModeRequest(
                    generation: generation,
                    connectionEpoch: connectionEpoch,
                    ok: ok,
                    message: ok ? nil : "Mode change failed: \(message ?? "unknown error")",
                    refreshIfAlreadySettled: true
                )
            }
        }
    }

    private func finishModeRequest(
        generation: Int,
        connectionEpoch: Int,
        ok: Bool,
        message: String?,
        refreshIfAlreadySettled: Bool
    ) {
        guard connectionEpoch == self.connectionEpoch else { return }
        guard pendingModeRequestGeneration == generation else {
            if refreshIfAlreadySettled && pendingModeRequestGeneration == nil {
                refreshStatus()
            }
            return
        }
        pendingModeRequestGeneration = nil
        if !ok {
            state?.appendLog(level: "error", message: message ?? "Mode change failed")
        }
        refreshStatus()
    }

    func addRule(_ rule: Rule) {
        guard let data = try? JSONEncoder().encode(rule) else { return }
        remote?.addRule(ruleJSON: data) { _, _ in }
    }

    func removeRule(id: UUID) {
        remote?.removeRule(idString: id.uuidString) { _, _ in }
    }

    func listRules(profile: String = "", completion: @MainActor @escaping ([Rule]) -> Void) {
        guard let connection else { return }
        let connectionEpoch = self.connectionEpoch
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in } as? HelperProtocol
        guard let proxy else { return }
        proxy.listRules(profile: profile) { [weak self, weak connection] data in
            guard let rules = try? JSONDecoder().decode([Rule].self, from: data) else { return }
            Task { @MainActor in
                guard let self, let connection,
                      connectionEpoch == self.connectionEpoch,
                      self.connection === connection else { return }
                completion(rules)
            }
        }
    }

    func startMonitoring() {
        remote?.startMonitoring { _, _ in }
    }

    func refreshBlocklists() {
        remote?.refreshBlocklists { [weak self] ok, message in
            guard !ok else { return }
            Task { @MainActor in
                self?.state?.appendLog(
                    level: "error",
                    message: message ?? "One or more blocklists failed to refresh; cached data remains active."
                )
            }
        }
    }

    func setEnforcementEnabled(_ enabled: Bool) {
        enforcementRequestGeneration &+= 1
        invalidatePendingStatusRequest()
        let generation = enforcementRequestGeneration
        pendingEnforcementRequestGeneration = generation
        let connectionEpoch = self.connectionEpoch
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            self?.finishEnforcementRequest(
                generation: generation,
                connectionEpoch: connectionEpoch,
                ok: false,
                message: "Enforcement change timed out",
                refreshIfAlreadySettled: false
            )
        }

        guard let connection else {
            finishEnforcementRequest(
                generation: generation,
                connectionEpoch: connectionEpoch,
                ok: false,
                message: "Enforcement change never reached the helper: no active XPC connection",
                refreshIfAlreadySettled: false
            )
            return
        }

        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self] error in
            Task { @MainActor in
                self?.finishEnforcementRequest(
                    generation: generation,
                    connectionEpoch: connectionEpoch,
                    ok: false,
                    message: "Enforcement change never reached the helper: \(error.localizedDescription)",
                    refreshIfAlreadySettled: true
                )
            }
        } as? HelperProtocol
        guard let proxy else {
            finishEnforcementRequest(
                generation: generation,
                connectionEpoch: connectionEpoch,
                ok: false,
                message: "Enforcement change never reached the helper: XPC proxy unavailable",
                refreshIfAlreadySettled: false
            )
            return
        }
        proxy.setEnforcementEnabled(enabled) { [weak self] ok, message in
            Task { @MainActor in
                self?.finishEnforcementRequest(
                    generation: generation,
                    connectionEpoch: connectionEpoch,
                    ok: ok,
                    message: ok ? nil : "Enforcement change failed: \(message ?? "unknown error")",
                    refreshIfAlreadySettled: true
                )
            }
        }
    }

    private func finishEnforcementRequest(
        generation: Int,
        connectionEpoch: Int,
        ok: Bool,
        message: String?,
        refreshIfAlreadySettled: Bool
    ) {
        guard connectionEpoch == self.connectionEpoch else { return }
        guard pendingEnforcementRequestGeneration == generation else {
            if refreshIfAlreadySettled && pendingEnforcementRequestGeneration == nil {
                refreshStatus()
            }
            return
        }
        // Settle each XPC request once; an error handler and reply can both
        // arrive, while status remains the authority for the desired toggle.
        pendingEnforcementRequestGeneration = nil
        if !ok {
            state?.appendLog(level: "error", message: message ?? "Enforcement change failed")
        }
        refreshStatus()
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
    weak var client: HelperClient?
    let connectionEpoch: Int

    init(state: AppState?, client: HelperClient, connectionEpoch: Int) {
        self.state = state
        self.client = client
        self.connectionEpoch = connectionEpoch
    }

    func notifyConnection(connectionJSON: Data) {
        guard let conns = try? JSONDecoder().decode([Connection].self, from: connectionJSON) else { return }
        Task { @MainActor in
            guard self.client?.isCurrentConnectionEpoch(self.connectionEpoch) == true else { return }
            self.state?.updateConnections(conns)
        }
    }

    func notifyTraffic(sampleJSON: Data) {
        guard let sample = try? JSONDecoder().decode(TrafficSample.self, from: sampleJSON) else { return }
        Task { @MainActor in
            guard self.client?.isCurrentConnectionEpoch(self.connectionEpoch) == true else { return }
            self.state?.appendSample(sample)
        }
    }

    func notifyAlert(connectionJSON: Data, reply: @escaping (Bool, Bool) -> Void) {
        guard let conn = try? JSONDecoder().decode(Connection.self, from: connectionJSON) else { reply(true, false); return }
        Task { @MainActor in
            guard self.client?.isCurrentConnectionEpoch(self.connectionEpoch) == true else {
                reply(false, false)
                return
            }
            self.state?.presentAlert(for: conn, reply: reply)
        }
    }

    func notifyLog(level: String, message: String) {
        Task { @MainActor in
            guard self.client?.isCurrentConnectionEpoch(self.connectionEpoch) == true else { return }
            self.state?.appendLog(level: level, message: message)
        }
    }
}
