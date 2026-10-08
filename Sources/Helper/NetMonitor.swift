import Foundation
import Darwin

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

struct NettopCounters: Equatable, Sendable {
    var bytesIn: Int64
    var bytesOut: Int64
}

/// One `nettop -L 1` run prints a frame of cumulative per-process counters.
/// Diffing per process means a process that closes its sockets costs at most
/// its own last interval instead of re-baselining every other process too.
struct NettopFrameDiffer: Sendable {
    private var previous: [String: NettopCounters] = [:]
    private(set) var hasBaseline = false

    /// Nil when the text carries no `,bytes_in,bytes_out,` header, so a failed
    /// run never becomes an empty frame that makes every process look new on
    /// the next one.
    static func parseFrame(_ text: String) -> [String: NettopCounters]? {
        var frame: [String: NettopCounters] = [:]
        var sawHeader = false
        for line in text.split(separator: "\n") {
            if line.hasPrefix(",bytes_in") { sawHeader = true; continue }
            let parts = line.split(separator: ",")
            guard parts.count >= 3,
                  let bytesIn = Int64(parts[parts.count - 2]),
                  let bytesOut = Int64(parts[parts.count - 1]) else { continue }
            let process = parts[..<(parts.count - 2)].joined(separator: ",")
            frame[process] = NettopCounters(bytesIn: bytesIn, bytesOut: bytesOut)
        }
        return sawHeader ? frame : nil
    }

    /// The first frame only seeds the baseline: its counters cover everything
    /// since each socket opened, not the last interval.
    mutating func ingest(_ frame: [String: NettopCounters]) -> NettopCounters? {
        defer { previous = frame; hasBaseline = true }
        guard hasBaseline else { return nil }
        var delta = NettopCounters(bytesIn: 0, bytesOut: 0)
        for (process, current) in frame {
            guard let last = previous[process] else {
                delta.bytesIn += current.bytesIn
                delta.bytesOut += current.bytesOut
                continue
            }
            // A drop means sockets closed between frames. Whatever they moved
            // in this interval is unattributable, so count nothing rather than
            // a negative.
            if current.bytesIn >= last.bytesIn { delta.bytesIn += current.bytesIn - last.bytesIn }
            if current.bytesOut >= last.bytesOut { delta.bytesOut += current.bytesOut - last.bytesOut }
        }
        return delta
    }

    mutating func reset() {
        previous.removeAll()
        hasBaseline = false
    }
}

final class NetMonitor: @unchecked Sendable {
    private var lsofTimer: DispatchSourceTimer?
    private var nettopTimer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "io.moamenbasel.puresnitch.netmon", qos: .utility)
    private let connectionStateLock = NSLock()
    private var connectionTracker = ActiveConnectionTracker()
    private var nettopDiffer = NettopFrameDiffer()
    private var nettopFailures = 0
    private var lastSampleTime = Date()
    private var pollPathCache: [Int32: String] = [:]
    private var bundleIDCache: [String: String?] = [:]

    var onConnections: (([Connection]) -> Void)?
    var onSample: ((TrafficSample) -> Void)?

    private(set) var isRunning = false

    func start() {
        stop()   // idempotent: tear down any existing pollers before (re)starting
        startLsofPolling()
        startNettopSampling()
        isRunning = true
    }

    func stop() {
        lsofTimer?.cancel(); lsofTimer = nil
        nettopTimer?.cancel(); nettopTimer = nil
        queue.async { [weak self] in
            self?.nettopDiffer.reset()
            self?.nettopFailures = 0
        }
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
        pollPathCache.removeAll(keepingCapacity: true)
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

    /// libproc answers from the kernel. The `ps -p` spawn this replaces cost
    /// one process launch per socket per poll, which on a busy Mac outran the
    /// two-second period and pinned a core (issue #19).
    private func pidPath(_ pid: Int32) -> String {
        if let cached = pollPathCache[pid] { return cached }
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        let path = length > 0 ? String(cString: buffer) : ""
        pollPathCache[pid] = path
        return path
    }

    private func bundleID(forPath path: String) -> String? {
        guard !path.isEmpty else { return nil }
        if let cached = bundleIDCache[path] { return cached }
        if bundleIDCache.count >= 512 { bundleIDCache.removeAll(keepingCapacity: true) }
        let id = Self.readBundleID(forPath: path)
        bundleIDCache[path] = .some(id)
        return id
    }

    private static func readBundleID(forPath path: String) -> String? {
        var p = path
        if let r = p.range(of: ".app/", options: .backwards) { p = String(p[..<r.upperBound]) }
        let plist = (p as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: plist)) else { return nil }
        guard let d = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return nil }
        return d["CFBundleIdentifier"] as? String
    }

    /// `nettop -L 0` busy-polls at well over a core no matter what `-s` says
    /// (measured 140% CPU at 1s, 2s and 5s), which is the sustained load issue
    /// #19 saw for weeks. A single `-L 1` sample costs about 20 ms of CPU, so
    /// sampling from a timer gives the same one-second cadence for a few
    /// percent of a core.
    private func startNettopSampling() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 0.5, repeating: .seconds(1))
        t.setEventHandler { [weak self] in self?.sampleNettop() }
        t.resume()
        nettopTimer = t
    }

    private func sampleNettop() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/nettop")
        p.arguments = ["-P", "-x", "-L", "1", "-J", "bytes_in,bytes_out"]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        do { try p.run() } catch { recordNettopFailure("nettop failed: \(error)"); return }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0,
              let text = String(data: data, encoding: .utf8),
              let frame = NettopFrameDiffer.parseFrame(text) else {
            recordNettopFailure("nettop exited \(p.terminationStatus) without a frame")
            return
        }
        nettopFailures = 0
        let now = Date()
        guard let delta = nettopDiffer.ingest(frame) else {
            lastSampleTime = now
            return
        }
        // The timer is one second; the floor only guards a clock step from
        // turning a small delta into an absurd rate.
        let dt = max(now.timeIntervalSince(lastSampleTime), 0.1)
        lastSampleTime = now
        onSample?(TrafficSample(timestamp: now,
                                bytesIn: Int64(Double(delta.bytesIn) / dt),
                                bytesOut: Int64(Double(delta.bytesOut) / dt)))
    }

    /// A failing nettop would otherwise log once a second forever.
    private func recordNettopFailure(_ message: String) {
        nettopFailures += 1
        if nettopFailures == 1 || nettopFailures % 60 == 0 {
            PSLog.error(PSLog.netmon, "\(message) (\(nettopFailures) consecutive)")
        }
    }
}
