import Foundation

public struct RuleMatcher: Sendable {
    public init() {}

    public func decision(for c: Connection, rules: [Rule], defaultMode: AppMode) -> RuleAction {
        let sorted = rules.filter { $0.enabled }.filter { rule in
            if let exp = rule.expiresAt, exp < Date() { return false }
            return true
        }.sorted { $0.priority > $1.priority }

        for r in sorted where matches(rule: r, connection: c) {
            return r.action
        }

        switch defaultMode {
        case .alert: return .ask
        case .silentAllow: return .allow
        case .silentDeny: return .deny
        }
    }

    public func matches(rule r: Rule, connection c: Connection) -> Bool {
        if r.direction != .any && r.direction != c.direction { return false }
        if let bid = r.processBundleId, !bid.isEmpty {
            if (c.processBundleId ?? "") != bid { return false }
        }
        if let path = r.processPath, !path.isEmpty {
            if c.processPath != path && !c.processPath.hasPrefix(path) { return false }
        }
        if let port = r.remotePort, port != 0 {
            if c.remotePort != port { return false }
        }
        if let host = r.remoteHost, !host.isEmpty {
            if !hostMatches(pattern: host, host: c.remoteHost) { return false }
        }
        if let ip = r.remoteIP, !ip.isEmpty {
            if !ipMatches(pattern: ip, ip: c.remoteIP) { return false }
        }
        return true
    }

    public func hostMatches(pattern: String, host: String) -> Bool {
        if pattern == host { return true }
        if pattern.hasPrefix("*.") {
            let suf = String(pattern.dropFirst(2))
            return host == suf || host.hasSuffix("." + suf)
        }
        if pattern.hasPrefix(".") {
            let suf = String(pattern.dropFirst())
            return host == suf || host.hasSuffix("." + suf)
        }
        return false
    }

    public func ipMatches(pattern: String, ip: String) -> Bool {
        if pattern == ip { return true }
        if pattern.contains("/") { return cidrContains(cidr: pattern, ip: ip) }
        if pattern.hasSuffix(".*") {
            let prefix = String(pattern.dropLast(2))
            return ip.hasPrefix(prefix + ".")
        }
        return false
    }

    private func cidrContains(cidr: String, ip: String) -> Bool {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let bits = Int(parts[1]), (0...32).contains(bits) else { return false }
        let net = String(parts[0])
        guard let a = ipv4ToUInt32(net), let b = ipv4ToUInt32(ip) else { return false }
        let mask: UInt32 = bits == 0 ? 0 : UInt32.max << (32 - bits)
        return (a & mask) == (b & mask)
    }

    private func ipv4ToUInt32(_ s: String) -> UInt32? {
        let octs = s.split(separator: ".")
        guard octs.count == 4 else { return nil }
        var v: UInt32 = 0
        for o in octs {
            guard let n = UInt32(o), n < 256 else { return nil }
            v = (v << 8) | n
        }
        return v
    }
}
