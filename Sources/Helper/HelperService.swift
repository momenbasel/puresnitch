import Foundation

final class HelperService: NSObject, HelperProtocol, @unchecked Sendable {
    private let store: RuleStore
    private let pf = PFManager()
    private let dns = DNSProxy()
    private let netmon = NetMonitor()
    private let blocklists: BlocklistManager
    private let listener: NSXPCListener
    private var clientConnections: [NSXPCConnection] = []
    private let clientLock = NSLock()
    private var pendingAsks: [String: (Bool) -> Void] = [:]
    private let askLock = NSLock()
    private var mode: AppMode = .alert

    init(listener: NSXPCListener) throws {
        let dbDir = "/Library/Application Support/PureSnitch"
        try? FileManager.default.createDirectory(atPath: dbDir, withIntermediateDirectories: true)
        let dbPath = (dbDir as NSString).appendingPathComponent("puresnitch.sqlite")
        self.store = try RuleStore(path: dbPath)
        self.blocklists = BlocklistManager(store: store)
        self.listener = listener
        super.init()

        if let modeStr = store.getSetting("mode"), let m = AppMode(rawValue: modeStr) {
            self.mode = m
        }

        dns.rules = store.allRules()
        dns.mode = mode
        dns.onBlock = { [weak self] domain, reason in
            self?.broadcast { c in
                let payload: [String: Any] = ["domain": domain, "reason": reason ?? ""]
                if let data = try? JSONSerialization.data(withJSONObject: payload) {
                    c.notifyLog(level: "block", message: "blocked: \(domain)")
                    _ = data
                }
            }
        }
        dns.onResolve = { [weak self] domain, ips in
            self?.broadcast { c in
                c.notifyLog(level: "resolve", message: "\(domain) -> \(ips.joined(separator: ", "))")
            }
        }
        dns.onAsk = { [weak self] domain, completion in
            guard let self else { completion(true); return }
            self.askLock.lock()
            self.pendingAsks[domain] = completion
            self.askLock.unlock()
            let stub = Connection(pid: 0, processName: "dns", processPath: "", remoteHost: domain, status: .pending)
            guard let data = try? JSONEncoder().encode(stub) else { completion(true); return }
            self.broadcast { c in
                c.notifyAlert(connectionJSON: data) { allow, _ in
                    self.askLock.lock()
                    let cb = self.pendingAsks.removeValue(forKey: domain)
                    self.askLock.unlock()
                    cb?(allow)
                }
            }
        }
        blocklists.onUpdate = { [weak self] _ in
            self?.dns.blocklist = self?.blocklists.domains ?? []
        }
        netmon.onConnections = { [weak self] conns in
            guard let self else { return }
            for c in conns {
                try? self.store.recordConnection(c)
            }
            self.broadcast { c in
                if let data = try? JSONEncoder().encode(conns) {
                    c.notifyConnection(connectionJSON: data)
                }
            }
        }
        netmon.onSample = { [weak self] sample in
            self?.broadcast { c in
                if let data = try? JSONEncoder().encode(sample) {
                    c.notifyTraffic(sampleJSON: data)
                }
            }
        }

        listener.delegate = self
    }

    func start() {
        listener.resume()
        netmon.start()
        Task { await blocklists.refresh() }
    }

    func registerClient(_ conn: NSXPCConnection) {
        clientLock.lock(); defer { clientLock.unlock() }
        clientConnections.append(conn)
    }

    func unregisterClient(_ conn: NSXPCConnection) {
        clientLock.lock(); defer { clientLock.unlock() }
        clientConnections.removeAll { $0 === conn }
    }

    private func broadcast(_ block: (HelperClientProtocol) -> Void) {
        clientLock.lock()
        let conns = clientConnections
        clientLock.unlock()
        for conn in conns {
            if let proxy = conn.remoteObjectProxy as? HelperClientProtocol {
                block(proxy)
            }
        }
    }

    // MARK: - HelperProtocol
    func getVersion(reply: @escaping (String) -> Void) { reply(AppConstants.version) }

    func getStatus(reply: @escaping (Data) -> Void) {
        let s = HelperStatus(
            version: AppConstants.version,
            running: netmon.isRunning,
            pfctlActive: pf.isLoaded,
            dnsProxyActive: dns.running,
            dnsProxyPort: Int(dns.port),
            activeRules: store.allRules().count,
            blockedToday: dns.statistics.blocked
        )
        reply((try? JSONEncoder().encode(s)) ?? Data())
    }

    func setMode(rawValue: String, reply: @escaping (Bool, String?) -> Void) {
        guard let m = AppMode(rawValue: rawValue) else { reply(false, "invalid mode"); return }
        self.mode = m
        dns.mode = m
        try? store.setSetting("mode", rawValue)
        reply(true, nil)
    }

    func reloadRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void) {
        do {
            let rules = try JSONDecoder().decode([Rule].self, from: rulesJSON)
            for r in rules { try store.upsertRule(r) }
            dns.rules = store.allRules()
            try pf.applyRules(dns.rules)
            reply(true, nil)
        } catch {
            reply(false, "\(error)")
        }
    }

    func addRule(ruleJSON: Data, reply: @escaping (Bool, String?) -> Void) {
        do {
            let rule = try JSONDecoder().decode(Rule.self, from: ruleJSON)
            try store.upsertRule(rule)
            dns.rules = store.allRules()
            try? pf.applyRules(dns.rules)
            reply(true, nil)
        } catch {
            reply(false, "\(error)")
        }
    }

    func removeRule(idString: String, reply: @escaping (Bool, String?) -> Void) {
        guard let id = UUID(uuidString: idString) else { reply(false, "bad uuid"); return }
        do {
            try store.deleteRule(id: id)
            dns.rules = store.allRules()
            try? pf.applyRules(dns.rules)
            reply(true, nil)
        } catch {
            reply(false, "\(error)")
        }
    }

    func listRules(profile: String, reply: @escaping (Data) -> Void) {
        let rules = store.allRules(profile: profile.isEmpty ? nil : profile)
        reply((try? JSONEncoder().encode(rules)) ?? Data())
    }

    /// Passive monitoring only. Starting the DNS proxy (which binds port 53 and
    /// takes over name resolution) and loading the pf anchor are *enforcement*
    /// and are gated behind setEnforcementEnabled — a monitor should never
    /// silently reconfigure the user's networking.
    func startMonitoring(reply: @escaping (Bool, String?) -> Void) {
        netmon.start()
        reply(true, nil)
    }

    func setEnforcementEnabled(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void) {
        if enabled {
            do {
                try pf.install()
                try dns.start(port: AppConstants.dnsProxyPort)
                reply(true, nil)
            } catch {
                _ = try? pf.uninstall()
                dns.stop()
                reply(false, "\(error)")
            }
        } else {
            dns.stop()
            do { try pf.uninstall(); reply(true, nil) } catch { reply(false, "\(error)") }
        }
    }

    func stopMonitoring(reply: @escaping (Bool, String?) -> Void) {
        dns.stop(); netmon.stop(); reply(true, nil)
    }

    func currentConnections(reply: @escaping (Data) -> Void) {
        let conns = store.recentConnections(limit: 500)
        reply((try? JSONEncoder().encode(conns)) ?? Data())
    }

    func currentTrafficSample(reply: @escaping (Data) -> Void) {
        let sample = TrafficSample(timestamp: Date(), bytesIn: 0, bytesOut: 0)
        reply((try? JSONEncoder().encode(sample)) ?? Data())
    }

    func enableBlocklist(idString: String, enabled: Bool, reply: @escaping (Bool, String?) -> Void) {
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
        Task {
            await self.blocklists.refresh()
            reply(true, nil)
        }
    }

    func setDoHUpstream(url: String, reply: @escaping (Bool, String?) -> Void) {
        dns.dohURL = url
        try? store.setSetting("doh_url", url)
        reply(true, nil)
    }

    func installPF(reply: @escaping (Bool, String?) -> Void) {
        do { try pf.install(); reply(true, nil) } catch { reply(false, "\(error)") }
    }

    func uninstallPF(reply: @escaping (Bool, String?) -> Void) {
        do { try pf.uninstall(); reply(true, nil) } catch { reply(false, "\(error)") }
    }

    func flushAll(reply: @escaping (Bool, String?) -> Void) {
        do { try pf.uninstall(); reply(true, nil) } catch { reply(false, "\(error)") }
    }

    func recentBlocked(limit: Int, reply: @escaping (Data) -> Void) {
        let conns = store.recentConnections(limit: limit, status: .denied)
        reply((try? JSONEncoder().encode(conns)) ?? Data())
    }

    func recentDenied(limit: Int, reply: @escaping (Data) -> Void) {
        let conns = store.recentConnections(limit: limit, status: .denied)
        reply((try? JSONEncoder().encode(conns)) ?? Data())
    }
}

extension HelperService: NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        guard Self.isTrustedClient(newConnection) else {
            PSLog.error(PSLog.helper, "rejected XPC client failing the code requirement (pid \(newConnection.processIdentifier))")
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

    /// This daemon runs as root and can rewrite the firewall, so it must not
    /// take orders from just any local process. Accept only code signed by the
    /// PureSnitch team with the app's identifier.
    ///
    /// Locally built (ad-hoc signed) helpers have no Team ID, and requiring one
    /// there would make every development build unable to talk to itself, so the
    /// check is enforced exactly when this helper is itself Developer ID signed
    /// - i.e. in anything users receive.
    static func isTrustedClient(_ connection: NSXPCConnection) -> Bool {
        guard selfIsTeamSigned else { return true }

        var code: SecCode?
        let attributes: [String: Any]
        if let tokenData = auditTokenData(for: connection) {
            attributes = [kSecGuestAttributeAudit as String: tokenData]
        } else {
            attributes = [kSecGuestAttributePid as String: connection.processIdentifier]
        }
        guard SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &code) == errSecSuccess,
              let code else { return false }

        let requirementText = "anchor apple generic"
            + " and identifier \"\(AppConstants.bundleIdGUI)\""
            + " and certificate leaf[subject.OU] = \"\(AppConstants.teamID)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    /// NSXPCConnection exposes the audit token only through KVC; fall back to
    /// the (racier) pid when that is unavailable.
    private static func auditTokenData(for connection: NSXPCConnection) -> Data? {
        guard connection.responds(to: NSSelectorFromString("auditToken")) else { return nil }
        guard let value = connection.value(forKey: "auditToken") as? NSValue else { return nil }
        var raw = audit_token_t()
        value.getValue(&raw, size: MemoryLayout<audit_token_t>.size)
        return withUnsafeBytes(of: &raw) { Data($0) }
    }

    /// True when this helper binary carries a Developer ID team identifier.
    private static let selfIsTeamSigned: Bool = {
        var code: SecStaticCode?
        let url = URL(fileURLWithPath: CommandLine.arguments.first ?? "/") as CFURL
        guard SecStaticCodeCreateWithPath(url, [], &code) == errSecSuccess, let code else { return false }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return false }
        return (dict["teamid"] as? String)?.isEmpty == false
    }()
}
