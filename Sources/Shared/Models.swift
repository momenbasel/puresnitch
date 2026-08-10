import Foundation

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
    public let running: Bool
    public let pfctlActive: Bool
    public let dnsProxyActive: Bool
    public let dnsProxyPort: Int
    public let activeRules: Int
    public let blockedToday: Int
    public init(version: String, running: Bool, pfctlActive: Bool, dnsProxyActive: Bool, dnsProxyPort: Int, activeRules: Int, blockedToday: Int) {
        self.version = version
        self.running = running
        self.pfctlActive = pfctlActive
        self.dnsProxyActive = dnsProxyActive
        self.dnsProxyPort = dnsProxyPort
        self.activeRules = activeRules
        self.blockedToday = blockedToday
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
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.2.0"
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
