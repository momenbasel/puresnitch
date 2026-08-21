import Foundation
import Darwin

public enum RuleAction: String, Codable, CaseIterable, Sendable {
    case allow
    case deny
    case ask
}

public enum RuleDirection: String, Codable, CaseIterable, Sendable {
    case outgoing
    case incoming
    case any
}

public enum RuleScope: String, Codable, CaseIterable, Sendable {
    case process
    case domain
    case ip
    case port
    case any
}

public enum AppMode: String, Codable, CaseIterable, Sendable {
    case alert
    case silentAllow
    case silentDeny
}

public struct Rule: Identifiable, Codable, Hashable, Sendable {
    public var id: UUID
    public var processBundleId: String?
    public var processPath: String?
    public var processName: String?
    public var remoteHost: String?
    public var remoteIP: String?
    public var remotePort: Int?
    public var direction: RuleDirection
    public var action: RuleAction
    public var scope: RuleScope
    public var priority: Int
    public var profile: String
    public var groupName: String?
    public var notes: String?
    public var enabled: Bool
    public var temporary: Bool
    public var createdAt: Date
    public var expiresAt: Date?
    public var lastUsedAt: Date?
    public var hitCount: Int

    public init(
        id: UUID = UUID(),
        processBundleId: String? = nil,
        processPath: String? = nil,
        processName: String? = nil,
        remoteHost: String? = nil,
        remoteIP: String? = nil,
        remotePort: Int? = nil,
        direction: RuleDirection = .outgoing,
        action: RuleAction = .ask,
        scope: RuleScope = .domain,
        priority: Int = 100,
        profile: String = "default",
        groupName: String? = nil,
        notes: String? = nil,
        enabled: Bool = true,
        temporary: Bool = false,
        createdAt: Date = Date(),
        expiresAt: Date? = nil,
        lastUsedAt: Date? = nil,
        hitCount: Int = 0
    ) {
        self.id = id
        self.processBundleId = processBundleId
        self.processPath = processPath
        self.processName = processName
        self.remoteHost = remoteHost
        self.remoteIP = remoteIP
        self.remotePort = remotePort
        self.direction = direction
        self.action = action
        self.scope = scope
        self.priority = priority
        self.profile = profile
        self.groupName = groupName
        self.notes = notes
        self.enabled = enabled
        self.temporary = temporary
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.lastUsedAt = lastUsedAt
        self.hitCount = hitCount
    }
}

public enum RuleValidationError: Error, LocalizedError, Sendable {
    case invalidRemoteHost
    case invalidRemoteIP
    case invalidRemotePort

    public var errorDescription: String? {
        switch self {
        case .invalidRemoteHost:
            return "The remote host is not a supported DNS, IPv4, or CIDR pattern."
        case .invalidRemoteIP:
            return "The remote IP is not a canonical IPv4 address or CIDR."
        case .invalidRemotePort:
            return "The remote port must be between 0 and 65535."
        }
    }
}

public extension Rule {
    /// Reject untrusted endpoint text before it can reach the root helper and
    /// become part of a pf ruleset. The helper must apply the same validation;
    /// this UI-side check gives immediate feedback and avoids optimistic state.
    func validateForPersistence() throws {
        if let host = remoteHost, !host.isEmpty,
           !Self.isValidRemoteHost(host) {
            throw RuleValidationError.invalidRemoteHost
        }
        if let ip = remoteIP, !ip.isEmpty,
           !Self.isValidRemoteIP(ip) {
            throw RuleValidationError.invalidRemoteIP
        }
        if let port = remotePort, !(0...65_535).contains(port) {
            throw RuleValidationError.invalidRemotePort
        }
    }

    static func isValidRemoteHost(_ raw: String) -> Bool {
        guard raw == raw.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty, raw.utf8.count <= 253,
              raw.unicodeScalars.allSatisfy(\.isASCII) else { return false }

        if isValidRemoteIP(raw) { return true }
        if raw.contains("."), raw.utf8.allSatisfy({ byte in
            (48...57).contains(byte) || byte == 46
        }) {
            return false
        }

        let host: Substring
        if raw.hasPrefix("*.") {
            host = raw.dropFirst(2)
        } else if raw.hasPrefix(".") {
            host = raw.dropFirst()
        } else {
            host = raw[...]
        }
        guard !host.isEmpty, !host.hasSuffix(".") else { return false }

        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        return labels.allSatisfy { label in
            guard !label.isEmpty, label.utf8.count <= 63,
                  label.first != "-", label.last != "-" else {
                return false
            }
            return label.utf8.allSatisfy { byte in
                Self.isASCIIAlphaNumeric(byte) || byte == 45 // "-"
            }
        }
    }

    static func isValidRemoteIP(_ raw: String) -> Bool {
        guard raw == raw.trimmingCharacters(in: .whitespacesAndNewlines),
              raw.unicodeScalars.allSatisfy(\.isASCII) else { return false }

        let parts = raw.split(separator: "/", omittingEmptySubsequences: false)
        if parts.count == 2 {
            guard canonicalIPv4(String(parts[0])) != nil,
                  let prefix = Int(parts[1]), String(prefix) == parts[1],
                  (0...32).contains(prefix) else { return false }
            return true
        }
        guard parts.count == 1 else { return false }
        return isIPv4Address(raw)
    }

    static func isIPv4Address(_ raw: String) -> Bool {
        canonicalIPv4(raw) != nil
    }

    /// IPv6 is detected so the UI can make the current IPv4-only rule
    /// limitation explicit instead of accidentally persisting a domain rule.
    static func isIPv6Address(_ raw: String) -> Bool {
        guard !raw.isEmpty else { return false }
        var candidate = raw[...]
        if candidate.first == "[", candidate.last == "]" {
            candidate = candidate.dropFirst().dropLast()
        }
        let addressText: Substring
        if let zoneSeparator = candidate.lastIndex(of: "%") {
            let zoneStart = candidate.index(after: zoneSeparator)
            guard zoneSeparator != candidate.startIndex, zoneStart < candidate.endIndex else { return false }
            addressText = candidate[..<zoneSeparator]
        } else {
            addressText = candidate
        }
        var address = in6_addr()
        return String(addressText).withCString { inet_pton(AF_INET6, $0, &address) == 1 }
    }

    private static func canonicalIPv4(_ raw: String) -> String? {
        let octets = raw.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return nil }
        var canonical: [String] = []
        for octet in octets {
            guard let value = Int(octet), (0...255).contains(value),
                  String(value) == octet else { return nil }
            canonical.append(String(value))
        }
        return canonical.joined(separator: ".")
    }

    private static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) ||
        (65...90).contains(byte) ||
        (97...122).contains(byte)
    }
}

public struct Connection: Identifiable, Codable, Hashable, Sendable {
    public enum Status: String, Codable, Sendable {
        case allowed
        case denied
        case pending
        case established
        case closed
    }

    public var id: UUID
    public var pid: Int32
    public var processName: String
    public var processPath: String
    public var processBundleId: String?
    public var localPort: Int
    public var remoteHost: String
    public var remoteIP: String
    public var remotePort: Int
    public var direction: RuleDirection
    public var status: Status
    public var protocolName: String
    public var bytesIn: Int64
    public var bytesOut: Int64
    public var country: String?
    public var countryCode: String?
    public var latitude: Double?
    public var longitude: Double?
    public var firstSeen: Date
    public var lastSeen: Date

    public init(
        id: UUID = UUID(),
        pid: Int32,
        processName: String,
        processPath: String,
        processBundleId: String? = nil,
        localPort: Int = 0,
        remoteHost: String = "",
        remoteIP: String = "",
        remotePort: Int = 0,
        direction: RuleDirection = .outgoing,
        status: Status = .pending,
        protocolName: String = "tcp",
        bytesIn: Int64 = 0,
        bytesOut: Int64 = 0,
        country: String? = nil,
        countryCode: String? = nil,
        latitude: Double? = nil,
        longitude: Double? = nil,
        firstSeen: Date = Date(),
        lastSeen: Date = Date()
    ) {
        self.id = id
        self.pid = pid
        self.processName = processName
        self.processPath = processPath
        self.processBundleId = processBundleId
        self.localPort = localPort
        self.remoteHost = remoteHost
        self.remoteIP = remoteIP
        self.remotePort = remotePort
        self.direction = direction
        self.status = status
        self.protocolName = protocolName
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.country = country
        self.countryCode = countryCode
        self.latitude = latitude
        self.longitude = longitude
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }
}

public struct Profile: Identifiable, Codable, Hashable, Sendable {
    public var id: UUID
    public var name: String
    public var mode: AppMode
    public var icon: String
    public var isActive: Bool
    public init(id: UUID = UUID(), name: String, mode: AppMode = .alert, icon: String = "shield", isActive: Bool = false) {
        self.id = id
        self.name = name
        self.mode = mode
        self.icon = icon
        self.isActive = isActive
    }
}

public struct TrafficSample: Codable, Sendable {
    public let timestamp: Date
    public let bytesIn: Int64
    public let bytesOut: Int64
    public init(timestamp: Date, bytesIn: Int64, bytesOut: Int64) {
        self.timestamp = timestamp
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
    }
}

public struct HelperStatus: Codable, Sendable {
    public let version: String
    public let mode: AppMode
    public let enforcementDesired: Bool
    public let legacyPFMigrationPending: Bool
    public let legacyPFReconciliationSucceeded: Bool
    public let running: Bool
    public let pfctlActive: Bool
    public let dnsProxyActive: Bool
    public let dnsProxyPort: Int
    public let activeRules: Int
    public let blockedToday: Int
    public init(version: String, mode: AppMode, enforcementDesired: Bool, legacyPFMigrationPending: Bool, legacyPFReconciliationSucceeded: Bool, running: Bool, pfctlActive: Bool, dnsProxyActive: Bool, dnsProxyPort: Int, activeRules: Int, blockedToday: Int) {
        self.version = version
        self.mode = mode
        self.enforcementDesired = enforcementDesired
        self.legacyPFMigrationPending = legacyPFMigrationPending
        self.legacyPFReconciliationSucceeded = legacyPFReconciliationSucceeded
        self.running = running
        self.pfctlActive = pfctlActive
        self.dnsProxyActive = dnsProxyActive
        self.dnsProxyPort = dnsProxyPort
        self.activeRules = activeRules
        self.blockedToday = blockedToday
    }

    private enum CodingKeys: String, CodingKey {
        case version
        case mode
        case enforcementDesired
        case legacyPFMigrationPending
        case legacyPFReconciliationSucceeded
        case running
        case pfctlActive
        case dnsProxyActive
        case dnsProxyPort
        case activeRules
        case blockedToday
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(String.self, forKey: .version)
        mode = try container.decodeIfPresent(AppMode.self, forKey: .mode) ?? .alert
        enforcementDesired = try container.decodeIfPresent(Bool.self, forKey: .enforcementDesired) ?? false
        legacyPFMigrationPending = try container.decodeIfPresent(
            Bool.self,
            forKey: .legacyPFMigrationPending
        ) ?? false
        legacyPFReconciliationSucceeded = try container.decodeIfPresent(
            Bool.self,
            forKey: .legacyPFReconciliationSucceeded
        ) ?? false
        running = try container.decode(Bool.self, forKey: .running)
        pfctlActive = try container.decode(Bool.self, forKey: .pfctlActive)
        dnsProxyActive = try container.decode(Bool.self, forKey: .dnsProxyActive)
        dnsProxyPort = try container.decode(Int.self, forKey: .dnsProxyPort)
        activeRules = try container.decode(Int.self, forKey: .activeRules)
        blockedToday = try container.decode(Int.self, forKey: .blockedToday)
    }
}

public struct BlocklistInfo: Codable, Sendable, Identifiable, Hashable {
    public var id: UUID
    public var name: String
    public var url: String
    public var enabled: Bool
    public var lastUpdated: Date?
    public var entryCount: Int
    public init(id: UUID = UUID(), name: String, url: String, enabled: Bool = true, lastUpdated: Date? = nil, entryCount: Int = 0) {
        self.id = id
        self.name = name
        self.url = url
        self.enabled = enabled
        self.lastUpdated = lastUpdated
        self.entryCount = entryCount
    }
}

public struct AppConstants {
    public static let bundleIdGUI = "io.moamenbasel.puresnitch"
    public static let bundleIdHelper = "io.moamenbasel.puresnitch.helper"
    public static let bundleIdNetExt = "io.moamenbasel.puresnitch.netext"
    public static let xpcMachServiceName = "io.moamenbasel.puresnitch.helper"
    /// App<->extension XPC. Must be prefixed by an app group the process owns,
    /// so a regular (non-daemon) app can vend it via NSXPCListener.
    public static let ipcMachServiceName = "H3WXHVTP97.io.moamenbasel.puresnitch.ipc"
    public static let appGroup = "H3WXHVTP97.io.moamenbasel.puresnitch"
    public static let teamID = "H3WXHVTP97"
    public static let version: String =
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.2.1"
    public static let dnsProxyPort: UInt16 = 53
    public static let defaultDoHUpstream = "https://cloudflare-dns.com/dns-query"

    public static var supportDir: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        let dir = base.appendingPathComponent("PureSnitch", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    public static var sharedDataDir: URL {
        let dir = URL(fileURLWithPath: "/Library/Application Support/PureSnitch", isDirectory: true)
        return dir
    }
}
