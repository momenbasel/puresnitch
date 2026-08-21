import Foundation
import Security

final class HelperService: NSObject, HelperProtocol, @unchecked Sendable {
    private static let supportDirectory = "/Library/Application Support/PureSnitch"
    private static let databaseName = "puresnitch.sqlite"
    private static let unauthorizedMessage = "unauthorized helper client"
    private let store: RuleStore
    private let pf = PFManager()
    private let dns = DNSProxy()
    private let netmon = NetMonitor()
    private let blocklists: BlocklistManager
    private let listener: NSXPCListener
    private var clientConnections: [NSXPCConnection] = []
    private let clientLock = NSLock()
    private let pendingAsks = PendingDNSAsks(capacity: 256)
    private let askTimeout: TimeInterval = 8
    private let stateLock = NSLock()
    private let mutationLock = NSRecursiveLock()
    private let ownerLock = NSLock()
    private var storedMode: AppMode = .alert
    private var storedEnforcementDesired = false
    private var enforcementDecisionPersisted = false
    private var storedLegacyPFMigrationPending = false
    private var storedLegacyPFReconciliationSucceeded = false
    private var ownerUID: uid_t?

    private var mode: AppMode {
        stateLock.lock(); defer { stateLock.unlock() }
        return storedMode
    }

    private var enforcementDesired: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return storedEnforcementDesired
    }

    private var hasPersistedEnforcementDecision: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return enforcementDecisionPersisted
    }

    private var legacyPFMigrationPending: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return storedLegacyPFMigrationPending
    }

    private var legacyPFReconciliationSucceeded: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return storedLegacyPFReconciliationSucceeded
    }

    init(listener: NSXPCListener) throws {
        let clientCodeRequirement = try Self.clientCodeSigningRequirement()
        try HelperSecurityState.prepareSupportDirectory(at: Self.supportDirectory)
        let dbPath = (Self.supportDirectory as NSString).appendingPathComponent(Self.databaseName)
        try HelperSecurityState.validateDatabasePathBeforeOpen(dbPath)
        let openedStore = try RuleStore(path: dbPath)
        try HelperSecurityState.hardenDatabaseFiles(dbPath)
        self.store = openedStore
        self.blocklists = BlocklistManager(store: openedStore)
        self.listener = listener
        let persistedDesired = openedStore.getSetting(HelperSecurityState.desiredSettingKey)
        self.storedEnforcementDesired = try HelperSecurityState.decodeDesired(persistedDesired)
        self.enforcementDecisionPersisted = persistedDesired != nil
        self.ownerUID = try HelperSecurityState.decodeOwnerUID(
            openedStore.getSetting(HelperSecurityState.ownerUIDSettingKey)
        )
        super.init()

        if let modeStr = store.getSetting("mode"), let m = AppMode(rawValue: modeStr) {
            self.storedMode = m
        }

        dns.rules = store.allRules(profile: "default")
        dns.mode = mode
        dns.onBlock = { [weak self] domain, reason in
            self?.broadcast { _, c in
                let payload: [String: Any] = ["domain": domain, "reason": reason ?? ""]
                if let data = try? JSONSerialization.data(withJSONObject: payload) {
                    c.notifyLog(level: "block", message: "blocked: \(domain)")
                    _ = data
                }
            }
        }
        dns.onResolve = { [weak self] domain, ips in
            self?.broadcast { _, c in
                c.notifyLog(level: "resolve", message: "\(domain) -> \(ips.joined(separator: ", "))")
            }
        }
        dns.onAsk = { [weak self] domain, completion in
            guard let self else { completion(true); return }
            self.handleDNSAsk(domain: domain, completion: completion)
        }
        blocklists.onUpdate = { [weak self] _ in
            self?.dns.blocklist = self?.blocklists.domains ?? []
        }
        netmon.onConnections = { [weak self] conns in
            guard let self else { return }
            do {
                try self.store.recordConnections(conns)
            } catch {
                PSLog.error(PSLog.netmon, "connection snapshot persistence failed: \(error)")
            }
            self.broadcast { _, c in
                if let data = try? JSONEncoder().encode(conns) {
                    c.notifyConnection(connectionJSON: data)
                }
            }
        }
        netmon.onSample = { [weak self] sample in
            self?.broadcast { _, c in
                if let data = try? JSONEncoder().encode(sample) {
                    c.notifyTraffic(sampleJSON: data)
                }
            }
        }

        listener.setConnectionCodeSigningRequirement(clientCodeRequirement)
        listener.delegate = self
    }

    func start() {
        mutationLock.lock()
        let hadPersistedDecision = hasPersistedEnforcementDecision
        recordLegacyPFReconciliation(
            migrationPending: !hadPersistedDecision,
            succeeded: false
        )

        var legacyStateDetected = false
        var legacyStateProbeFailed = false
        do {
            legacyStateDetected = try pf.hasLegacyState()
        } catch {
            // Unknown legacy state is never permission to replace a ruleset.
            // Keep migration pending until the signed GUI obtains an explicit
            // choice about the current v0.2.1 rules.
            legacyStateDetected = true
            legacyStateProbeFailed = true
            PSLog.error(PSLog.pf, "legacy PF state inspection failed: \(error)")
        }

        if legacyStateDetected {
            recordLegacyPFReconciliation(migrationPending: true, succeeded: false)
        }

        if legacyStateDetected {
            PSLog.info(
                PSLog.pf,
                "legacy PF migration is pending an explicit ruleset decision; existing rules were preserved"
            )
        } else {
            var canReconcile = true
            if !hadPersistedDecision {
                do {
                    // A genuinely fresh installation has no legacy state. Make
                    // its default-off decision durable before clearing or
                    // adopting any managed runtime state.
                    try persistDesiredEnforcement(false)
                } catch {
                    canReconcile = false
                    PSLog.error(PSLog.pf, "could not persist fresh-install enforcement intent: \(error)")
                }
            }

            var runtimeReconciled = false
            if canReconcile {
                do {
                    if enforcementDesired {
                        try activateEnforcementRuntime()
                    } else {
                        try pf.cleanupOrphanedState()
                    }
                    runtimeReconciled = true
                } catch {
                    PSLog.error(PSLog.pf, "startup enforcement reconciliation failed: \(error)")
                }
            }
            let legacySucceeded = pf.latestLegacyReconciliationSucceeded == true
            recordLegacyPFReconciliation(
                migrationPending: legacyStateDetected && !(runtimeReconciled && legacySucceeded),
                succeeded: legacySucceeded
            )
            if legacyStateProbeFailed && !legacySucceeded {
                PSLog.error(PSLog.pf, "legacy PF migration remains unresolved after startup reconciliation")
            }
        }
        netmon.start()
        mutationLock.unlock()
        listener.resume()
        Task { await blocklists.refresh() }
    }

    /// Signal handlers dispatch here on a normal queue. Runtime state is
    /// removed only when doing so agrees with durable or migration-pending
    /// intent; otherwise PF remains live for the replacement helper.
    func shutdown() {
        mutationLock.lock()
        defer { mutationLock.unlock() }
        if legacyPFMigrationPending {
            // A missing historical intent is not permission to remove rules.
            // Explicit GUI repair or Homebrew cleanup resolves this state.
            drainPendingAsksUsingCurrentMode()
            dns.stop()
            netmon.stop()
            return
        }
        if enforcementDesired {
            // Keep the validated PF subanchor and our enable reference live
            // across a normal launchd restart. The next helper instance reloads
            // the authoritative rules before reopening DNS.
            drainPendingAsksUsingCurrentMode()
            dns.stop()
            netmon.stop()
            return
        }
        do {
            try stopEnforcementRuntimePreservingDesired()
        } catch {
            PSLog.error(PSLog.pf, "shutdown PF cleanup failed: \(error)")
            return
        }
        netmon.stop()
    }

    private static func clientCodeSigningRequirement() throws -> String {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
            throw NSError(
                domain: "HelperService",
                code: 30,
                userInfo: [NSLocalizedDescriptionKey: "could not inspect the helper code signature"]
            )
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw NSError(
                domain: "HelperService",
                code: 31,
                userInfo: [NSLocalizedDescriptionKey: "could not inspect the helper static signature"]
            )
        }
        var signingInfo: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &signingInfo
        ) == errSecSuccess, let info = signingInfo as? [String: Any] else {
            throw NSError(
                domain: "HelperService",
                code: 32,
                userInfo: [NSLocalizedDescriptionKey: "could not read helper signing information"]
            )
        }

        let identifier = "identifier \"\(AppConstants.bundleIdGUI)\""
        guard let team = info["teamid"] as? String, !team.isEmpty else {
            // Ad-hoc source builds have no certificate chain. Identifier plus
            // the console-admin/owner UID policy preserves local development
            // without the release build's former allow-all behavior.
            return identifier
        }
        guard team == AppConstants.teamID else {
            throw NSError(
                domain: "HelperService",
                code: 33,
                userInfo: [NSLocalizedDescriptionKey: "helper signing team does not match the configured release team"]
            )
        }
        return "anchor apple generic and \(identifier)"
            + " and certificate leaf[subject.OU] = \"\(AppConstants.teamID)\""
    }

    func registerClient(_ conn: NSXPCConnection) {
        clientLock.lock(); defer { clientLock.unlock() }
        clientConnections.append(conn)
    }

    func unregisterClient(_ conn: NSXPCConnection) {
        clientLock.lock()
        clientConnections.removeAll { $0 === conn }
        let noClientsRemain = clientConnections.isEmpty
        clientLock.unlock()
        if noClientsRemain {
            drainPendingAsksUsingCurrentMode()
        }
    }

    @discardableResult
    private func broadcast(_ block: (NSXPCConnection, HelperClientProtocol) -> Void) -> Int {
        clientLock.lock()
        let conns = clientConnections
        clientLock.unlock()
        var delivered = 0
        for conn in conns {
            guard isAuthorizedExistingClient(conn) else {
                unregisterClient(conn)
                conn.invalidate()
                continue
            }
            if let proxy = conn.remoteObjectProxy as? HelperClientProtocol {
                block(conn, proxy)
                delivered += 1
            } else {
                unregisterClient(conn)
                conn.invalidate()
            }
        }
        return delivered
    }

    private func handleDNSAsk(domain: String, completion: @escaping (Bool) -> Void) {
        let stub = Connection(pid: 0, processName: "dns", processPath: "", remoteHost: domain, status: .pending)
        guard let data = try? JSONEncoder().encode(stub) else {
            completion(fallbackAllowsDNSAsk)
            return
        }

        clientLock.lock()
        let hasClients = !clientConnections.isEmpty
        clientLock.unlock()
        guard hasClients else {
            completion(fallbackAllowsDNSAsk)
            return
        }

        guard let askID = pendingAsks.register(completion) else {
            let allow = fallbackAllowsDNSAsk
            PSLog.error(PSLog.dns, "pending DNS alert limit reached; using current mode for \(domain)")
            completion(allow)
            return
        }

        let delivered = broadcast { [weak self] connection, client in
            client.notifyAlert(connectionJSON: data) { allow, _ in
                guard let self else { return }
                guard self.isAuthorizedExistingClient(connection) else {
                    self.unregisterClient(connection)
                    connection.invalidate()
                    self.settlePendingAsk(id: askID, allow: self.fallbackAllowsDNSAsk)
                    return
                }
                self.settlePendingAsk(id: askID, allow: allow)
            }
        }
        guard delivered > 0 else {
            settlePendingAsk(id: askID, allow: fallbackAllowsDNSAsk)
            return
        }

        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + askTimeout) { [weak self] in
            guard let self else { return }
            if self.settlePendingAsk(id: askID, allow: self.fallbackAllowsDNSAsk) {
                PSLog.error(PSLog.dns, "DNS alert timed out; using current mode for \(domain)")
            }
        }
    }

    @discardableResult
    private func settlePendingAsk(id: UUID, allow: Bool) -> Bool {
        pendingAsks.settle(id: id, allow: allow)
    }

    private var fallbackAllowsDNSAsk: Bool { mode != .silentDeny }

    private func drainPendingAsksUsingCurrentMode() {
        pendingAsks.drain(allow: fallbackAllowsDNSAsk)
    }

    private func persistDesiredEnforcement(_ desired: Bool) throws {
        try store.setSetting(
            HelperSecurityState.desiredSettingKey,
            HelperSecurityState.encodeDesired(desired)
        )
        stateLock.lock()
        storedEnforcementDesired = desired
        enforcementDecisionPersisted = true
        stateLock.unlock()
    }

    /// Store success last. A crash between writes can therefore produce only a
    /// conservative false result, never a stale successful migration claim.
    @discardableResult
    private func recordLegacyPFReconciliation(migrationPending: Bool, succeeded: Bool) -> Bool {
        let checkedSuccess = succeeded && !migrationPending
        do {
            try store.setSetting(
                HelperSecurityState.legacyPFReconciliationSettingKey,
                HelperSecurityState.encodeDesired(false)
            )
            try store.setSetting(
                HelperSecurityState.legacyPFMigrationPendingSettingKey,
                HelperSecurityState.encodeDesired(migrationPending)
            )
            if checkedSuccess {
                try store.setSetting(
                    HelperSecurityState.legacyPFReconciliationSettingKey,
                    HelperSecurityState.encodeDesired(true)
                )
            }
            stateLock.lock()
            storedLegacyPFMigrationPending = migrationPending
            storedLegacyPFReconciliationSucceeded = checkedSuccess
            stateLock.unlock()
            return true
        } catch {
            stateLock.lock()
            storedLegacyPFMigrationPending = true
            storedLegacyPFReconciliationSucceeded = false
            stateLock.unlock()
            PSLog.error(PSLog.pf, "could not persist legacy PF reconciliation status: \(error)")
            return false
        }
    }

    /// Reconcile the runtime to the already-persisted desired state. PF is
    /// installed first so DNS cannot report enforcement while the firewall
    /// transaction is still incomplete.
    private func activateEnforcementRuntime() throws {
        if pf.isLoaded && dns.running
            && !legacyPFMigrationPending && legacyPFReconciliationSucceeded { return }
        try Self.validateRules(dns.rules)
        if legacyPFMigrationPending {
            try activateEnforcementWhilePreservingLegacyState()
            return
        }
        do {
            try pf.install(rules: dns.rules)
            try dns.start(port: AppConstants.dnsProxyPort)
        } catch {
            let activationError = error
            drainPendingAsksUsingCurrentMode()
            dns.stop()
            do {
                try pf.uninstall()
            } catch let rollbackError {
                throw NSError(
                    domain: "HelperService",
                    code: 20,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "enforcement failed: \(activationError); firewall rollback also failed: \(rollbackError)"
                    ]
                )
            }
            throw activationError
        }
    }

    private func activateEnforcementWhilePreservingLegacyState() throws {
        do {
            try pf.installCurrentStatePreservingLegacy(rules: dns.rules)
        } catch {
            let activationError = error
            do {
                try pf.uninstallCurrentStatePreservingLegacy()
            } catch let rollbackError {
                throw NSError(
                    domain: "HelperService",
                    code: 21,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "current firewall staging failed: \(activationError); "
                            + "rollback while preserving legacy rules also failed: \(rollbackError)"
                    ]
                )
            }
            throw activationError
        }

        do {
            try dns.start(port: AppConstants.dnsProxyPort)
        } catch {
            let activationError = error
            drainPendingAsksUsingCurrentMode()
            dns.stop()
            do {
                try pf.uninstallCurrentStatePreservingLegacy()
            } catch let rollbackError {
                throw NSError(
                    domain: "HelperService",
                    code: 22,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "DNS activation failed: \(activationError); current firewall rollback failed: \(rollbackError)"
                    ]
                )
            }
            throw activationError
        }

        // Cleanup is deliberately last. If it fails, current PF and DNS remain
        // active alongside the legacy state, avoiding a fail-open rollback.
        try pf.reconcileLegacyState()
    }

    /// Runtime-only cleanup used during process replacement. The persisted
    /// desired state deliberately survives so the next helper restores it.
    private func stopEnforcementRuntimePreservingDesired() throws {
        try pf.uninstall()
        drainPendingAsksUsingCurrentMode()
        dns.stop()
    }

    /// Explicit user disable. Persist the off intent before teardown so a crash
    /// cannot make the next helper re-enable enforcement the administrator just
    /// disabled. PF remains truthfully observable and DNS stays running if the
    /// checked teardown fails; startup will retry cleanup because desired=false.
    private func disableEnforcementRuntime() throws {
        try persistDesiredEnforcement(false)
        try pf.uninstall()
        drainPendingAsksUsingCurrentMode()
        dns.stop()
    }

    // MARK: - HelperProtocol
    func getVersion(reply: @escaping (String) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply("") }) else { return }
        reply(AppConstants.version)
    }

    func getStatus(reply: @escaping (Data) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(Data()) }) else { return }
        mutationLock.lock(); defer { mutationLock.unlock() }
        let s = HelperStatus(
            version: AppConstants.version,
            mode: mode,
            enforcementDesired: enforcementDesired,
            legacyPFMigrationPending: legacyPFMigrationPending,
            legacyPFReconciliationSucceeded: legacyPFReconciliationSucceeded,
            running: netmon.isRunning,
            pfctlActive: pf.isLoaded,
            dnsProxyActive: dns.running,
            dnsProxyPort: Int(dns.port),
            activeRules: store.allRules(profile: "default").count,
            blockedToday: dns.statistics.blocked
        )
        reply((try? JSONEncoder().encode(s)) ?? Data())
    }

    func setMode(rawValue: String, reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        mutationLock.lock(); defer { mutationLock.unlock() }
        guard let m = AppMode(rawValue: rawValue) else { reply(false, "invalid mode"); return }
        do {
            try store.setSetting("mode", rawValue)
            stateLock.lock()
            storedMode = m
            stateLock.unlock()
            dns.mode = m
            reply(true, nil)
        } catch {
            reply(false, "mode was not saved: \(error)")
        }
    }

    func reloadRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        mutationLock.lock(); defer { mutationLock.unlock() }
        do {
            let rules = try JSONDecoder().decode([Rule].self, from: rulesJSON)
            try Self.validateRules(rules)
            for r in rules { try store.upsertRule(r) }
            dns.rules = store.allRules(profile: "default")
            try applyRulesIfEnforcing()
            reply(true, nil)
        } catch {
            reply(false, "\(error)")
        }
    }

    func addRule(ruleJSON: Data, reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        mutationLock.lock(); defer { mutationLock.unlock() }
        do {
            let rule = try JSONDecoder().decode(Rule.self, from: ruleJSON)
            try Self.validateRule(rule)
            try store.upsertRule(rule)
            dns.rules = store.allRules(profile: "default")
            // Saved but not enforced is a real difference; say so instead of
            // reporting plain success.
            do { try applyRulesIfEnforcing() } catch {
                reply(false, "rule saved but the firewall refused it: \(error)")
                return
            }
            reply(true, nil)
        } catch {
            reply(false, "\(error)")
        }
    }

    func removeRule(idString: String, reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        mutationLock.lock(); defer { mutationLock.unlock() }
        guard let id = UUID(uuidString: idString) else { reply(false, "bad uuid"); return }
        do {
            try store.deleteRule(id: id)
            dns.rules = store.allRules(profile: "default")
            do { try applyRulesIfEnforcing() } catch {
                reply(false, "rule removed but the firewall refused the update: \(error)")
                return
            }
            reply(true, nil)
        } catch {
            reply(false, "\(error)")
        }
    }

    func listRules(profile: String, reply: @escaping (Data) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(Data()) }) else { return }
        let rules = store.allRules(profile: profile.isEmpty ? nil : profile)
        reply((try? JSONEncoder().encode(rules)) ?? Data())
    }

    /// Passive monitoring only. The loopback DNS listener and pf anchor are
    /// enforcement components gated behind setEnforcementEnabled. Starting the
    /// listener does not change the Mac's system DNS configuration.
    func startMonitoring(reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        mutationLock.lock(); defer { mutationLock.unlock() }
        netmon.start()
        reply(true, nil)
    }

    /// pf only has an anchor loaded while enforcement is on; pushing rules at it
    /// otherwise is both pointless and a source of phantom errors.
    private func applyRulesIfEnforcing() throws {
        guard enforcementDesired else { return }
        try Self.validateRules(dns.rules)
        if pf.isLoaded && dns.running
            && !legacyPFMigrationPending && legacyPFReconciliationSucceeded {
            try pf.applyRules(dns.rules)
        } else {
            try activateEnforcementRuntime()
        }
    }

    func setEnforcementEnabled(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        setEnforcementEnabledAuthorized(enabled, mayResolveLegacyMigration: true, reply: reply)
    }

    private func setEnforcementEnabledAuthorized(
        _ enabled: Bool,
        mayResolveLegacyMigration: Bool,
        reply: @escaping (Bool, String?) -> Void
    ) {
        mutationLock.lock(); defer { mutationLock.unlock() }
        let migrationWasPending = legacyPFMigrationPending
        guard !migrationWasPending || mayResolveLegacyMigration else {
            reply(false, "legacy firewall migration requires setEnforcementEnabled")
            return
        }
        if enabled {
            if enforcementDesired && pf.isLoaded && dns.running
                && !migrationWasPending && legacyPFReconciliationSucceeded {
                reply(true, nil)
                return
            }
            do {
                // Persist intent first. A crash during reconciliation will then
                // cause the restarted helper to retry instead of silently
                // forgetting that the administrator enabled enforcement.
                try persistDesiredEnforcement(true)
                try activateEnforcementRuntime()
                guard pf.latestLegacyReconciliationSucceeded == true else {
                    recordLegacyPFReconciliation(
                        migrationPending: migrationWasPending,
                        succeeded: false
                    )
                    reply(false, "legacy firewall reconciliation did not complete")
                    return
                }
                guard recordLegacyPFReconciliation(migrationPending: false, succeeded: true) else {
                    reply(false, "legacy firewall reconciliation status was not saved")
                    return
                }
                reply(true, nil)
            } catch {
                let activationError = error
                // activateEnforcementRuntime performs checked rollback. Clear
                // desired intent only when PF truthfully reports no retained
                // current state and no legacy migration is being preserved;
                // otherwise keep desired=true for a safe retry.
                if !pf.isLoaded && !migrationWasPending {
                    do {
                        try persistDesiredEnforcement(false)
                    } catch let persistenceError {
                        reply(
                            false,
                            "enforcement failed: \(activationError); clearing desired state also failed: \(persistenceError)"
                        )
                        recordLegacyPFReconciliation(
                            migrationPending: migrationWasPending,
                            succeeded: false
                        )
                        return
                    }
                }
                recordLegacyPFReconciliation(
                    migrationPending: migrationWasPending,
                    succeeded: false
                )
                reply(false, "enforcement was not enabled: \(activationError)")
            }
        } else {
            do {
                try disableEnforcementRuntime()
            } catch {
                recordLegacyPFReconciliation(
                    migrationPending: migrationWasPending,
                    succeeded: false
                )
                reply(false, "firewall removal failed; DNS proxy was left running: \(error)")
                return
            }
            guard pf.latestLegacyReconciliationSucceeded == true else {
                recordLegacyPFReconciliation(
                    migrationPending: migrationWasPending,
                    succeeded: false
                )
                reply(false, "legacy firewall reconciliation did not complete")
                return
            }
            guard recordLegacyPFReconciliation(migrationPending: false, succeeded: true) else {
                reply(false, "legacy firewall reconciliation status was not saved")
                return
            }
            reply(true, nil)
        }
    }

    func prepareForUnregistration(reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        mutationLock.lock(); defer { mutationLock.unlock() }
        if legacyPFMigrationPending {
            // Replacement may stop this helper, but unresolved legacy rules
            // remain until the owner explicitly chooses enforcement on or off.
            drainPendingAsksUsingCurrentMode()
            dns.stop()
            netmon.stop()
            reply(true, nil)
            return
        }
        do {
            try stopEnforcementRuntimePreservingDesired()
            netmon.stop()
            guard pf.latestLegacyReconciliationSucceeded == true else {
                recordLegacyPFReconciliation(migrationPending: false, succeeded: false)
                reply(false, "runtime was cleaned up but legacy firewall reconciliation was not verified")
                return
            }
            guard recordLegacyPFReconciliation(migrationPending: false, succeeded: true) else {
                reply(false, "runtime was cleaned up but reconciliation status was not saved")
                return
            }
            reply(true, nil)
        } catch {
            recordLegacyPFReconciliation(migrationPending: false, succeeded: false)
            reply(false, "runtime cleanup failed; helper removal was not authorized: \(error)")
        }
    }

    func stopMonitoring(reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        mutationLock.lock(); defer { mutationLock.unlock() }
        guard !legacyPFMigrationPending else {
            reply(false, "legacy firewall migration requires an explicit enforcement decision")
            return
        }
        do {
            try disableEnforcementRuntime()
        } catch {
            recordLegacyPFReconciliation(migrationPending: false, succeeded: false)
            reply(false, "monitoring was not stopped because enforcement removal failed: \(error)")
            return
        }
        netmon.stop()
        guard pf.latestLegacyReconciliationSucceeded == true,
              recordLegacyPFReconciliation(migrationPending: false, succeeded: true) else {
            reply(false, "monitoring stopped but legacy firewall reconciliation was not verified")
            return
        }
        reply(true, nil)
    }

    func currentConnections(reply: @escaping (Data) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(Data()) }) else { return }
        let conns = store.recentConnections(limit: 500)
        reply((try? JSONEncoder().encode(conns)) ?? Data())
    }

    func currentTrafficSample(reply: @escaping (Data) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(Data()) }) else { return }
        let sample = TrafficSample(timestamp: Date(), bytesIn: 0, bytesOut: 0)
        reply((try? JSONEncoder().encode(sample)) ?? Data())
    }

    func enableBlocklist(idString: String, enabled: Bool, reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        mutationLock.lock(); defer { mutationLock.unlock() }
        let lists = store.allBlocklists()
        guard let target = lists.first(where: { $0.id.uuidString == idString }) else {
            reply(false, "blocklist not found"); return
        }
        var updated = target
        updated.enabled = enabled
        do { try store.updateBlocklist(updated); reply(true, nil) } catch { reply(false, "\(error)") }
        Task { await self.blocklists.refresh() }
    }

    func refreshBlocklists(reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        Task {
            let summary = await self.blocklists.refresh()
            guard summary.failures.isEmpty else {
                let message = "Refreshed \(summary.refreshed) blocklists; partial failures: "
                    + summary.failures.joined(separator: "; ")
                PSLog.error(PSLog.dns, message)
                reply(false, message)
                return
            }
            reply(true, nil)
        }
    }

    func setDoHUpstream(url: String, reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        mutationLock.lock(); defer { mutationLock.unlock() }
        do {
            try store.setSetting("doh_url", url)
            dns.dohURL = url
            reply(true, nil)
        } catch {
            reply(false, "DoH upstream was not saved: \(error)")
        }
    }

    func installPF(reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        guard !legacyPFMigrationPending else {
            reply(false, "legacy firewall migration requires setEnforcementEnabled")
            return
        }
        setEnforcementEnabledAuthorized(true, mayResolveLegacyMigration: false, reply: reply)
    }

    func uninstallPF(reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        guard !legacyPFMigrationPending else {
            reply(false, "legacy firewall migration requires setEnforcementEnabled")
            return
        }
        setEnforcementEnabledAuthorized(false, mayResolveLegacyMigration: false, reply: reply)
    }

    func flushAll(reply: @escaping (Bool, String?) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(false, Self.unauthorizedMessage) }) else { return }
        guard !legacyPFMigrationPending else {
            reply(false, "legacy firewall migration requires setEnforcementEnabled")
            return
        }
        setEnforcementEnabledAuthorized(false, mayResolveLegacyMigration: false, reply: reply)
    }

    func recentBlocked(limit: Int, reply: @escaping (Data) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(Data()) }) else { return }
        let conns = store.recentConnections(limit: limit, status: .denied)
        reply((try? JSONEncoder().encode(conns)) ?? Data())
    }

    func recentDenied(limit: Int, reply: @escaping (Data) -> Void) {
        guard authorizeCurrentXPCRequest(orReject: { reply(Data()) }) else { return }
        let conns = store.recentConnections(limit: limit, status: .denied)
        reply((try? JSONEncoder().encode(conns)) ?? Data())
    }

    private static func validateRules(_ rules: [Rule]) throws {
        for rule in rules { try validateRule(rule) }
    }

    private static func validateRule(_ rule: Rule) throws {
        try rule.validateForPersistence()
    }

    private func authorizeAndClaim(peerUID: uid_t) -> Bool {
        ownerLock.lock()
        let persistedOwner = ownerUID
        let persistedOwnerIsAdmin = persistedOwner.map { HelperSecurityState.isAdmin(uid: $0) } ?? false
        let ownerNeedsRecovery = persistedOwner != nil && !persistedOwnerIsAdmin
        let consoleUID = (persistedOwner == nil || ownerNeedsRecovery)
            ? HelperSecurityState.consoleUID()
            : nil
        let peerIsAdmin = HelperSecurityState.isAdmin(uid: peerUID)
        guard HelperAuthorizationPolicy.allows(
            peerUID: peerUID,
            persistedOwnerUID: persistedOwner,
            persistedOwnerIsAdmin: persistedOwnerIsAdmin,
            consoleUID: consoleUID,
            peerIsAdmin: peerIsAdmin
        ) else {
            ownerLock.unlock()
            return false
        }

        guard persistedOwner == nil || ownerNeedsRecovery else {
            ownerLock.unlock()
            return true
        }
        do {
            try store.setSetting(
                HelperSecurityState.ownerUIDSettingKey,
                HelperSecurityState.encodeOwnerUID(peerUID)
            )
            ownerUID = peerUID
            ownerLock.unlock()
            if let persistedOwner, persistedOwner != peerUID {
                revokeAllClientConnectionsAfterOwnerChange()
            }
            return true
        } catch {
            ownerLock.unlock()
            PSLog.error(PSLog.helper, "could not persist the helper owner UID")
            return false
        }
    }

    private func isAuthorizedExistingClient(_ connection: NSXPCConnection) -> Bool {
        let peerUID = connection.effectiveUserIdentifier
        ownerLock.lock()
        let owner = ownerUID
        ownerLock.unlock()
        return HelperAuthorizationPolicy.allowsExistingClient(
            peerUID: peerUID,
            ownerUID: owner,
            peerIsAdmin: HelperSecurityState.isAdmin(uid: peerUID)
        )
    }

    private func revokeAllClientConnectionsAfterOwnerChange() {
        clientLock.lock()
        let revoked = clientConnections
        clientConnections.removeAll()
        clientLock.unlock()
        drainPendingAsksUsingCurrentMode()
        for connection in revoked { connection.invalidate() }
    }

    private func authorizeCurrentXPCRequest(orReject rejection: () -> Void) -> Bool {
        guard let connection = NSXPCConnection.current() else {
            rejection()
            return false
        }
        guard authorizeAndClaim(peerUID: connection.effectiveUserIdentifier) else {
            rejection()
            connection.scheduleSendBarrierBlock { connection.invalidate() }
            return false
        }
        return true
    }

}

extension HelperService: NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        // NSXPCListener applies the immutable code-signing requirement before
        // invoking this delegate. The effective UID comes from XPC credentials,
        // not a PID lookup, so it is not vulnerable to PID reuse.
        let peerUID = newConnection.effectiveUserIdentifier
        guard authorizeAndClaim(peerUID: peerUID) else {
            PSLog.error(PSLog.helper, "rejected XPC client UID \(peerUID) by owner/console-admin policy")
            return false
        }
        newConnection.exportedInterface = HelperBridge.remoteInterface()
        newConnection.exportedObject = self
        newConnection.remoteObjectInterface = HelperBridge.exportedInterface()
        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            if let c = newConnection { self?.unregisterClient(c) }
        }
        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            if let c = newConnection { self?.unregisterClient(c) }
        }
        registerClient(newConnection)
        newConnection.resume()
        return true
    }
}
