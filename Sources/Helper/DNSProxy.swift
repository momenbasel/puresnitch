import Foundation
import Network

final class DNSProxy: @unchecked Sendable {
    private enum ListenerPhase { case stopped, starting, running }

    private var udpListener: NWListener?
    private var tcpListener: NWListener?
    private var listenerPhase: ListenerPhase = .stopped
    private var listenerGeneration: UUID?
    private var listeningPort: UInt16 = 53
    private let lifecycleLock = NSLock()

    private var tcpIdleTimers: [ObjectIdentifier: (generation: UUID, timer: DispatchSourceTimer)] = [:]
    private var activeConnections: [ObjectIdentifier: NWConnection] = [:]
    private let connectionLock = NSLock()
    private var acceptingConnections = false

    private var storedBlocklist: Set<String> = []
    private var storedRules: [Rule] = []
    private var storedMode: AppMode = .alert
    private var storedDoHURL: String = AppConstants.defaultDoHUpstream
    private var storedOnBlock: ((String, String?) -> Void)?
    private var storedOnResolve: ((String, [String]) -> Void)?
    private var storedOnAsk: ((String, @escaping (Bool) -> Void) -> Void)?
    private let policyLock = NSLock()
    private let matcher = RuleMatcher()

    private let queue = DispatchQueue(label: "io.moamenbasel.puresnitch.dns", qos: .userInitiated)
    private let listenerStartupTimeout: TimeInterval = 5
    private let tcpIdleTimeout: TimeInterval = 15

    var port: UInt16 {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        return listeningPort
    }
    var running: Bool {
        lifecycleLock.lock(); defer { lifecycleLock.unlock() }
        return listenerPhase == .running
    }

    var blocklist: Set<String> {
        get { withPolicyLock { storedBlocklist } }
        set { withPolicyLock { storedBlocklist = newValue } }
    }
    var rules: [Rule] {
        get { withPolicyLock { storedRules } }
        set { withPolicyLock { storedRules = newValue } }
    }
    var mode: AppMode {
        get { withPolicyLock { storedMode } }
        set { withPolicyLock { storedMode = newValue } }
    }
    var dohURL: String {
        get { withPolicyLock { storedDoHURL } }
        set { withPolicyLock { storedDoHURL = newValue } }
    }
    var onBlock: ((String, String?) -> Void)? {
        get { withPolicyLock { storedOnBlock } }
        set { withPolicyLock { storedOnBlock = newValue } }
    }
    var onResolve: ((String, [String]) -> Void)? {
        get { withPolicyLock { storedOnResolve } }
        set { withPolicyLock { storedOnResolve = newValue } }
    }
    var onAsk: ((String, @escaping (Bool) -> Void) -> Void)? {
        get { withPolicyLock { storedOnAsk } }
        set { withPolicyLock { storedOnAsk = newValue } }
    }

    private let stats = DNSStats()

    var statistics: (queries: Int, blocked: Int, allowed: Int) { stats.snapshot() }

    private struct PolicySnapshot {
        let blocklist: Set<String>
        let rules: [Rule]
        let mode: AppMode
        let dohURL: String
        let onBlock: ((String, String?) -> Void)?
        let onResolve: ((String, [String]) -> Void)?
        let onAsk: ((String, @escaping (Bool) -> Void) -> Void)?
    }

    @discardableResult
    private func withPolicyLock<T>(_ body: () -> T) -> T {
        policyLock.lock()
        defer { policyLock.unlock() }
        return body()
    }

    private func policySnapshot() -> PolicySnapshot {
        withPolicyLock {
            PolicySnapshot(
                blocklist: storedBlocklist,
                rules: storedRules,
                mode: storedMode,
                dohURL: storedDoHURL,
                onBlock: storedOnBlock,
                onResolve: storedOnResolve,
                onAsk: storedOnAsk
            )
        }
    }

    func start(port: UInt16 = 53) throws {
        lifecycleLock.lock()
        if listenerPhase == .running {
            lifecycleLock.unlock()
            return
        }
        guard listenerPhase == .stopped else {
            lifecycleLock.unlock()
            throw NSError(
                domain: "DNSProxy",
                code: 4,
                userInfo: [NSLocalizedDescriptionKey: "DNS listeners are already starting"]
            )
        }
        let generation = UUID()
        listenerPhase = .starting
        listenerGeneration = generation
        listeningPort = port
        lifecycleLock.unlock()

        guard let p = NWEndpoint.Port(rawValue: port) else {
            stop(expectedGeneration: generation)
            throw NSError(domain: "DNSProxy", code: 1, userInfo: [NSLocalizedDescriptionKey: "bad port"])
        }

        do {
            let udpGate = ListenerStartGate(label: "UDP")
            let params = NWParameters.udp
            params.allowLocalEndpointReuse = true
            params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: p)
            let udp = try NWListener(using: params)
            udp.newConnectionLimit = 128
            udp.newConnectionHandler = { [weak self] conn in self?.handleUDP(conn, generation: generation) }
            udp.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    udpGate.succeed()
                case .failed(let err):
                    udpGate.fail(err)
                    PSLog.error(PSLog.dns, "udp listener failed: \(err)")
                    self?.handleListenerFailure(generation: generation)
                case .cancelled:
                    udpGate.fail(DNSProxy.listenerCancelledError(protocolName: "UDP"))
                    self?.handleListenerFailure(generation: generation)
                default:
                    break
                }
            }

            let tcpGate = ListenerStartGate(label: "TCP")
            let tparams = NWParameters.tcp
            tparams.allowLocalEndpointReuse = true
            tparams.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: p)
            let tcp = try NWListener(using: tparams)
            tcp.newConnectionLimit = 128
            tcp.newConnectionHandler = { [weak self] conn in self?.handleTCP(conn, generation: generation) }
            tcp.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    tcpGate.succeed()
                case .failed(let err):
                    tcpGate.fail(err)
                    PSLog.error(PSLog.dns, "tcp listener failed: \(err)")
                    self?.handleListenerFailure(generation: generation)
                case .cancelled:
                    tcpGate.fail(DNSProxy.listenerCancelledError(protocolName: "TCP"))
                    self?.handleListenerFailure(generation: generation)
                default:
                    break
                }
            }

            lifecycleLock.lock()
            guard listenerGeneration == generation, listenerPhase == .starting else {
                lifecycleLock.unlock()
                throw DNSProxy.listenerCancelledError(protocolName: "DNS")
            }
            udpListener = udp
            tcpListener = tcp
            connectionLock.lock()
            acceptingConnections = true
            connectionLock.unlock()
            lifecycleLock.unlock()
            udp.start(queue: queue)
            tcp.start(queue: queue)

            try udpGate.wait(timeout: listenerStartupTimeout)
            try tcpGate.wait(timeout: listenerStartupTimeout)

            lifecycleLock.lock()
            guard listenerGeneration == generation, listenerPhase == .starting else {
                lifecycleLock.unlock()
                throw DNSProxy.listenerCancelledError(protocolName: "DNS")
            }
            listenerPhase = .running
            lifecycleLock.unlock()
            PSLog.info(PSLog.dns, "dns proxy listening on 127.0.0.1:\(port) (udp+tcp)")
        } catch {
            stop(expectedGeneration: generation)
            throw error
        }
    }

    func stop() {
        stop(expectedGeneration: nil)
    }

    private func stop(expectedGeneration: UUID?) {
        lifecycleLock.lock()
        if let expectedGeneration, listenerGeneration != expectedGeneration {
            lifecycleLock.unlock()
            return
        }
        let udp = udpListener
        let tcp = tcpListener
        udpListener = nil; tcpListener = nil
        listenerPhase = .stopped
        listenerGeneration = nil
        lifecycleLock.unlock()

        connectionLock.lock()
        acceptingConnections = false
        let timers = tcpIdleTimers.values.map(\.timer)
        let connections = Array(activeConnections.values)
        tcpIdleTimers.removeAll()
        activeConnections.removeAll()
        connectionLock.unlock()
        udp?.cancel(); tcp?.cancel()
        for timer in timers { timer.cancel() }
        for connection in connections { connection.cancel() }
    }

    private func handleListenerFailure(generation: UUID) {
        stop(expectedGeneration: generation)
    }

    private static func listenerCancelledError(protocolName: String) -> NSError {
        NSError(
            domain: "DNSProxy",
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: "\(protocolName) listener was cancelled before becoming ready"]
        )
    }

    // MARK: - UDP path
    private func handleUDP(_ conn: NWConnection, generation: UUID) {
        guard registerConnection(conn, listenerGeneration: generation) else {
            conn.cancel()
            return
        }
        conn.start(queue: queue)
        receiveUDP(conn)
    }

    private func receiveUDP(_ conn: NWConnection) {
        conn.receiveMessage { [weak self] data, _, _, _ in
            guard let self, let data = data, !data.isEmpty else {
                self?.removeConnection(conn)
                conn.cancel()
                return
            }
            self.process(payload: data, isTCP: false) { reply in
                guard let reply else {
                    self.removeConnection(conn)
                    conn.cancel()
                    return
                }
                conn.send(content: reply, completion: .contentProcessed { [weak self] _ in
                    self?.removeConnection(conn)
                    conn.cancel()
                })
            }
        }
    }

    // MARK: - TCP path
    private func handleTCP(_ conn: NWConnection, generation: UUID) {
        guard registerConnection(conn, listenerGeneration: generation) else {
            conn.cancel()
            return
        }
        conn.start(queue: queue)
        armTCPIdleTimeout(conn)
        readTCP(conn, accumulated: Data())
    }
    private func readTCP(_ conn: NWConnection, accumulated: Data) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] data, _, isComplete, error in
            guard let self else { conn.cancel(); return }
            guard error == nil, !isComplete, let data, !data.isEmpty else {
                self.removeConnection(conn)
                conn.cancel()
                return
            }
            self.armTCPIdleTimeout(conn)
            var buf = accumulated + data
            while buf.count >= 2 {
                let len = (Int(buf[0]) << 8) | Int(buf[1])
                if buf.count < 2 + len { break }
                let payload = buf.subdata(in: 2..<(2+len))
                buf.removeSubrange(0..<(2+len))
                self.process(payload: payload, isTCP: true) { reply in
                    guard let reply else { return }
                    var framed = Data()
                    framed.append(UInt8((reply.count >> 8) & 0xff))
                    framed.append(UInt8(reply.count & 0xff))
                    framed.append(reply)
                    conn.send(content: framed, completion: .contentProcessed { _ in })
                }
            }
            self.readTCP(conn, accumulated: buf)
        }
    }

    private func armTCPIdleTimeout(_ conn: NWConnection) {
        let key = ObjectIdentifier(conn)
        let timerGeneration = UUID()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + tcpIdleTimeout)
        timer.setEventHandler { [weak self, weak conn] in
            guard let self else { return }
            self.connectionLock.lock()
            let isCurrentTimer = self.tcpIdleTimers[key]?.generation == timerGeneration
            let expiredTimer = isCurrentTimer ? self.tcpIdleTimers.removeValue(forKey: key)?.timer : nil
            let expiredConnection = isCurrentTimer ? self.activeConnections.removeValue(forKey: key) : nil
            self.connectionLock.unlock()
            guard isCurrentTimer else { return }
            expiredTimer?.cancel()
            (expiredConnection ?? conn)?.cancel()
        }
        timer.resume()
        connectionLock.lock()
        guard acceptingConnections, activeConnections[key] != nil else {
            connectionLock.unlock()
            timer.cancel()
            conn.cancel()
            return
        }
        let replacedTimer = tcpIdleTimers.updateValue((timerGeneration, timer), forKey: key)?.timer
        connectionLock.unlock()
        replacedTimer?.cancel()
    }

    private func registerConnection(_ conn: NWConnection, listenerGeneration generation: UUID) -> Bool {
        lifecycleLock.lock()
        let listenerIsCurrent = listenerGeneration == generation && listenerPhase != .stopped
        lifecycleLock.unlock()
        guard listenerIsCurrent else { return false }

        let key = ObjectIdentifier(conn)
        connectionLock.lock()
        defer { connectionLock.unlock() }
        guard acceptingConnections else { return false }
        activeConnections[key] = conn
        return true
    }

    private func removeConnection(_ conn: NWConnection) {
        let key = ObjectIdentifier(conn)
        connectionLock.lock()
        let timer = tcpIdleTimers.removeValue(forKey: key)?.timer
        activeConnections.removeValue(forKey: key)
        connectionLock.unlock()
        timer?.cancel()
    }

    // MARK: - DNS processing
    private func process(payload: Data, isTCP: Bool, reply: @escaping (Data?) -> Void) {
        stats.incrQueries()
        guard let q = DNSWire.firstQuestion(payload) else {
            reply(nil); return
        }
        let domain = q.name.lowercased()
        let policy = policySnapshot()
        let connStub = Connection(pid: 0, processName: "", processPath: "", remoteHost: domain, direction: .outgoing, status: .pending)
        let action = matcher.decision(for: connStub, rules: policy.rules, defaultMode: policy.mode)

        if action == .deny || isBlocklisted(domain, in: policy.blocklist) {
            stats.incrBlocked()
            policy.onBlock?(domain, nil)
            if let resp = DNSWire.nxResponse(for: payload) { reply(resp) } else { reply(nil) }
            return
        }

        if action == .ask {
            guard let onAsk = policy.onAsk else {
                // With no decision client, derive the fallback from the current
                // mode instead of leaving the DNS request suspended forever.
                if policy.mode == .silentDeny {
                    stats.incrBlocked()
                    policy.onBlock?(domain, "no-alert-client")
                    reply(DNSWire.nxResponse(for: payload))
                } else {
                    forwardDoH(payload: payload, domain: domain, policy: policy, reply: reply)
                }
                return
            }
            onAsk(domain) { [weak self] allow in
                guard let self else {
                    reply(nil)
                    return
                }
                if !allow {
                    self.stats.incrBlocked()
                    policy.onBlock?(domain, "ask-denied")
                    if let resp = DNSWire.nxResponse(for: payload) { reply(resp) } else { reply(nil) }
                    return
                }
                self.forwardDoH(payload: payload, domain: domain, policy: policy, reply: reply)
            }
            return
        }

        forwardDoH(payload: payload, domain: domain, policy: policy, reply: reply)
    }

    private func isBlocklisted(_ domain: String, in blocklist: Set<String>) -> Bool {
        if blocklist.contains(domain) { return true }
        var parts = domain.split(separator: ".")
        while parts.count >= 2 {
            let candidate = parts.joined(separator: ".")
            if blocklist.contains(candidate) { return true }
            parts.removeFirst()
        }
        return false
    }

    private func forwardDoH(
        payload: Data,
        domain: String,
        policy: PolicySnapshot,
        reply: @escaping (Data?) -> Void
    ) {
        stats.incrAllowed()
        guard let url = URL(string: policy.dohURL) else { reply(nil); return }
        var req = URLRequest(url: url, timeoutInterval: 5)
        req.httpMethod = "POST"
        req.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        req.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        req.httpBody = payload
        let task = URLSession.shared.dataTask(with: req) { data, _, _ in
            if let data = data {
                if let ips = DNSWire.extractAnswers(data) {
                    policy.onResolve?(domain, ips)
                }
                reply(data)
            } else {
                reply(nil)
            }
        }
        task.resume()
    }
}

private final class ListenerStartGate: @unchecked Sendable {
    private let condition = NSCondition()
    private let label: String
    private var result: Result<Void, Error>?

    init(label: String) {
        self.label = label
    }

    func succeed() {
        finish(.success(()))
    }

    func fail(_ error: Error) {
        finish(.failure(error))
    }

    func wait(timeout: TimeInterval) throws {
        condition.lock()
        defer { condition.unlock() }
        let deadline = Date().addingTimeInterval(timeout)
        while result == nil && condition.wait(until: deadline) {}
        guard let result else {
            throw NSError(
                domain: "DNSProxy",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "\(label) listener did not become ready within \(Int(timeout)) seconds"]
            )
        }
        try result.get()
    }

    private func finish(_ newResult: Result<Void, Error>) {
        condition.lock()
        if result == nil {
            result = newResult
            condition.broadcast()
        }
        condition.unlock()
    }
}

final class DNSStats: @unchecked Sendable {
    private let lock = NSLock()
    private var queries = 0
    private var blocked = 0
    private var allowed = 0
    func incrQueries() { lock.lock(); queries += 1; lock.unlock() }
    func incrBlocked() { lock.lock(); blocked += 1; lock.unlock() }
    func incrAllowed() { lock.lock(); allowed += 1; lock.unlock() }
    func snapshot() -> (queries: Int, blocked: Int, allowed: Int) {
        lock.lock(); defer { lock.unlock() }
        return (queries, blocked, allowed)
    }
}

enum DNSWire {
    struct Question { let name: String; let type: UInt16; let cls: UInt16 }

    static func firstQuestion(_ data: Data) -> Question? {
        guard data.count > 12 else { return nil }
        var pos = 12
        guard let (name, end) = readName(data, from: pos) else { return nil }
        pos = end
        guard pos + 4 <= data.count else { return nil }
        let type = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
        let cls = UInt16(data[pos+2]) << 8 | UInt16(data[pos+3])
        return Question(name: name, type: type, cls: cls)
    }

    static func readName(_ data: Data, from start: Int) -> (String, Int)? {
        var labels: [String] = []
        var pos = start
        var jumped = false
        var endOfFirstName = start
        var safety = 0
        while pos < data.count {
            safety += 1
            if safety > 128 { return nil }
            let len = Int(data[pos])
            if len == 0 {
                pos += 1
                if !jumped { endOfFirstName = pos }
                return (labels.joined(separator: "."), endOfFirstName)
            }
            if (len & 0xc0) == 0xc0 {
                guard pos + 1 < data.count else { return nil }
                let offset = ((len & 0x3f) << 8) | Int(data[pos+1])
                if !jumped { endOfFirstName = pos + 2 }
                pos = offset
                jumped = true
                continue
            }
            pos += 1
            guard pos + len <= data.count else { return nil }
            let label = data.subdata(in: pos..<(pos+len))
            labels.append(String(data: label, encoding: .utf8) ?? "?")
            pos += len
        }
        return nil
    }

    static func nxResponse(for query: Data) -> Data? {
        guard query.count > 12 else { return nil }
        var resp = query
        // flags: QR=1, AA=1, RCODE=3 (NXDOMAIN), RD copied
        let rd = resp[2] & 0x01
        resp[2] = 0x80 | rd // QR=1
        resp[3] = 0x83      // RA=1, RCODE=3 NXDOMAIN
        // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        resp[6] = 0; resp[7] = 0
        resp[8] = 0; resp[9] = 0
        resp[10] = 0; resp[11] = 0
        return resp
    }

    static func extractAnswers(_ data: Data) -> [String]? {
        guard data.count > 12 else { return nil }
        let ancount = Int(UInt16(data[6]) << 8 | UInt16(data[7]))
        guard ancount > 0 else { return [] }
        var pos = 12
        // skip question
        guard let q = firstQuestion(data) else { return nil }
        _ = q
        if let (_, end) = readName(data, from: 12) { pos = end + 4 } else { return nil }
        var out: [String] = []
        for _ in 0..<ancount {
            guard let (_, end) = readName(data, from: pos) else { break }
            pos = end
            guard pos + 10 <= data.count else { break }
            let type = UInt16(data[pos]) << 8 | UInt16(data[pos+1])
            let rdlen = Int(UInt16(data[pos+8]) << 8 | UInt16(data[pos+9]))
            pos += 10
            guard pos + rdlen <= data.count else { break }
            if type == 1 && rdlen == 4 {
                let ip = "\(data[pos]).\(data[pos+1]).\(data[pos+2]).\(data[pos+3])"
                out.append(ip)
            } else if type == 28 && rdlen == 16 {
                var parts: [String] = []
                for i in stride(from: 0, to: 16, by: 2) {
                    let v = UInt16(data[pos+i]) << 8 | UInt16(data[pos+i+1])
                    parts.append(String(format: "%x", v))
                }
                out.append(parts.joined(separator: ":"))
            }
            pos += rdlen
        }
        return out
    }
}
