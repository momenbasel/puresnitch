import Foundation

struct SocketIdentity: Hashable, Sendable {
    let pid: Int32
    let processPath: String
    let localAddress: String
    let localPort: Int
    let remoteAddress: String
    let remotePort: Int
    let direction: RuleDirection
    let protocolName: String
}

struct SocketObservation: Sendable {
    var connection: Connection
    let identity: SocketIdentity
}

struct ActiveConnectionTracker: Sendable {
    private struct Session: Sendable {
        let id: UUID
        let firstSeen: Date
    }

    private var active: [SocketIdentity: Session] = [:]

    /// Carry identity only while a socket is present in consecutive snapshots.
    /// Once it disappears, a later reuse of the same 5-tuple is a new session.
    mutating func reconcile(_ observations: [SocketObservation], seenAt: Date) -> [Connection] {
        var next: [SocketIdentity: Session] = [:]
        var seen: Set<SocketIdentity> = []
        var connections: [Connection] = []
        connections.reserveCapacity(observations.count)

        for observation in observations where seen.insert(observation.identity).inserted {
            var connection = observation.connection
            if let session = active[observation.identity] {
                connection.id = session.id
                connection.firstSeen = session.firstSeen
            } else {
                connection.id = UUID()
                connection.firstSeen = seenAt
            }
            connection.lastSeen = seenAt
            next[observation.identity] = Session(id: connection.id, firstSeen: connection.firstSeen)
            connections.append(connection)
        }
        active = next
        return connections
    }

    mutating func reset() {
        active.removeAll(keepingCapacity: true)
    }
}

final class NetMonitor: @unchecked Sendable {
    private var lsofTimer: DispatchSourceTimer?
    private var nettopProc: Process?
    private let queue = DispatchQueue(label: "io.moamenbasel.puresnitch.netmon", qos: .utility)
    private let connectionStateLock = NSLock()
    private var connectionTracker = ActiveConnectionTracker()

    var onConnections: (([Connection]) -> Void)?
    var onSample: ((TrafficSample) -> Void)?

    private var lastIn: Int64 = 0
    private var lastOut: Int64 = 0
    private var lastSampleTime = Date()
    private var hasBaseline = false
    private var pending = ""
    private var frame: [String] = []
    private(set) var isRunning = false

    func start() {
        stop()   // idempotent: tear down any existing pollers before (re)starting
        startLsofPolling()
        startNettop()
        isRunning = true
    }

    func stop() {
        lsofTimer?.cancel(); lsofTimer = nil
        nettopProc?.terminate(); nettopProc = nil
        pending = ""; frame = []; hasBaseline = false
        connectionStateLock.lock()
        connectionTracker.reset()
        connectionStateLock.unlock()
        isRunning = false
    }

    private func startLsofPolling() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 1.0, repeating: .seconds(2))
        t.setEventHandler { [weak self] in self?.pollLsof() }
        t.resume()
        lsofTimer = t
    }

    private func pollLsof() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        p.arguments = ["-i", "-n", "-P", "-F", "pcnPT"]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        do { try p.run() } catch { return }
        // Drain the pipe BEFORE waiting. `lsof -i` on a busy Mac easily exceeds
        // the 64 KB pipe buffer, and waiting first deadlocks the monitor queue
        // permanently: lsof blocks writing, we block waiting, and the
        // connection list never updates again.
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard let txt = String(data: data, encoding: .utf8) else { return }

        var observations: [SocketObservation] = []
        var pid: Int32 = 0
        var pname = ""
        var protocolName = "tcp"
        for line in txt.split(separator: "\n") {
            guard let first = line.first else { continue }
            let rest = String(line.dropFirst())
            switch first {
            case "p":
                pid = Int32(rest) ?? 0
                protocolName = "tcp"
            case "c":
                pname = rest
            case "P":
                protocolName = rest.lowercased()
            case "n":
                if let observation = parseN(
                    line: rest,
                    pid: pid,
                    name: pname,
                    protocolName: protocolName
                ) {
                    observations.append(observation)
                }
            default: break
            }
        }
        connectionStateLock.lock()
        let conns = connectionTracker.reconcile(observations, seenAt: Date())
        connectionStateLock.unlock()
        onConnections?(conns)
    }

    private func parseN(
        line: String,
        pid: Int32,
        name: String,
        protocolName: String
    ) -> SocketObservation? {
        guard line.contains("->") else { return nil }
        let parts = line.split(separator: " ").map(String.init)
        let addrPart = parts.first ?? line
        let halves = addrPart.split(separator: "-", maxSplits: 1).map(String.init)
        guard halves.count == 2 else { return nil }
        let local = halves[0]
        let remoteRaw = halves[1].hasPrefix(">") ? String(halves[1].dropFirst()) : halves[1]
        guard let (lip, lport) = splitHostPort(local) else { return nil }
        guard let (rip, rport) = splitHostPort(remoteRaw) else { return nil }
        let path = pidPath(pid)
        let bundle = bundleID(forPath: path)
        let normalizedProtocol = protocolName.isEmpty ? "tcp" : protocolName.lowercased()
        let connection = Connection(
            pid: pid,
            processName: name,
            processPath: path,
            processBundleId: bundle,
            localPort: lport,
            remoteHost: rip,
            remoteIP: rip,
            remotePort: rport,
            direction: .outgoing,
            status: .established,
            protocolName: normalizedProtocol
        )
        let identity = SocketIdentity(
            pid: pid,
            processPath: path,
            localAddress: lip,
            localPort: lport,
            remoteAddress: rip,
            remotePort: rport,
            direction: .outgoing,
            protocolName: normalizedProtocol
        )
        return SocketObservation(connection: connection, identity: identity)
    }

    private func splitHostPort(_ s: String) -> (String, Int)? {
        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]") else { return nil }
            let host = String(s[s.index(after: s.startIndex)..<close])
            let after = s.index(after: close)
            guard after < s.endIndex, s[after] == ":" else { return nil }
            let port = Int(s[s.index(after: after)...]) ?? 0
            return (host, port)
        }
        guard let lastColon = s.lastIndex(of: ":") else { return nil }
        let host = String(s[s.startIndex..<lastColon])
        let portStr = s[s.index(after: lastColon)...]
        return (host, Int(portStr) ?? 0)
    }

    private func pidPath(_ pid: Int32) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/ps")
        p.arguments = ["-p", String(pid), "-o", "comm="]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        do { try p.run() } catch { return "" }
        p.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    private func bundleID(forPath path: String) -> String? {
        guard !path.isEmpty else { return nil }
        var p = path
        if let r = p.range(of: ".app/", options: .backwards) { p = String(p[..<r.upperBound]) }
        let plist = (p as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: plist)) else { return nil }
        guard let d = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return nil }
        return d["CFBundleIdentifier"] as? String
    }

    private func startNettop() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/nettop")
        p.arguments = ["-P", "-x", "-L", "0", "-J", "bytes_in,bytes_out", "-s", "1"]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        do { try p.run() } catch { PSLog.error(PSLog.netmon, "nettop failed: \(error)"); return }
        nettopProc = p
        pending = ""; frame = []; hasBaseline = false; lastIn = 0; lastOut = 0

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            guard let self else { return }
            let data = handle.availableData
            if data.isEmpty { return }
            guard let s = String(data: data, encoding: .utf8) else { return }
            self.ingestNettop(s)
        }
    }

    /// nettop writes one *frame* per interval: a `,bytes_in,bytes_out,` header
    /// followed by one cumulative line per process. A pipe read is not a frame -
    /// it can split mid-line or carry half a frame - so summing whatever arrived
    /// and diffing it against the previous sum produced nonsense rates
    /// (multi-GB/s spikes). Buffer, cut on the header, and only diff whole frames.
    private func ingestNettop(_ chunk: String) {
        pending += chunk
        while let nl = pending.firstIndex(of: "\n") {
            let line = String(pending[pending.startIndex..<nl])
            pending = String(pending[pending.index(after: nl)...])
            if line.hasPrefix(",bytes_in") {
                if !frame.isEmpty { completeFrame(frame) }
                frame = []
            } else if !line.isEmpty {
                frame.append(line)
            }
        }
    }

    private func completeFrame(_ lines: [String]) {
        var totalIn: Int64 = 0
        var totalOut: Int64 = 0
        for line in lines {
            let parts = line.split(separator: ",")
            guard parts.count >= 3,
                  let bin = Int64(parts[parts.count - 2]),
                  let bout = Int64(parts[parts.count - 1]) else { continue }
            totalIn += bin
            totalOut += bout
        }
        let now = Date()

        // The first frame is only a baseline: nettop counters are cumulative
        // since it started, so emitting a rate here would report the whole
        // history as if it happened in one second.
        guard hasBaseline else {
            hasBaseline = true
            lastIn = totalIn; lastOut = totalOut; lastSampleTime = now
            return
        }

        let dt = now.timeIntervalSince(lastSampleTime)
        guard dt >= 0.4 else { return }
        // Counters only go up while nettop lives; a drop means processes exited,
        // so treat it as a fresh baseline instead of a negative or huge delta.
        guard totalIn >= lastIn, totalOut >= lastOut else {
            lastIn = totalIn; lastOut = totalOut; lastSampleTime = now
            return
        }
        let deltaIn = totalIn - lastIn
        let deltaOut = totalOut - lastOut
        lastIn = totalIn; lastOut = totalOut; lastSampleTime = now
        let sample = TrafficSample(timestamp: now,
                                   bytesIn: Int64(Double(deltaIn) / dt),
                                   bytesOut: Int64(Double(deltaOut) / dt))
        onSample?(sample)
    }
}
