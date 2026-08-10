import Foundation

@objc public protocol HelperProtocol {
    func getVersion(reply: @escaping (String) -> Void)
    func getStatus(reply: @escaping (Data) -> Void)
    func setMode(rawValue: String, reply: @escaping (Bool, String?) -> Void)

    func reloadRules(rulesJSON: Data, reply: @escaping (Bool, String?) -> Void)
    func addRule(ruleJSON: Data, reply: @escaping (Bool, String?) -> Void)
    func removeRule(idString: String, reply: @escaping (Bool, String?) -> Void)
    func listRules(profile: String, reply: @escaping (Data) -> Void)

    func startMonitoring(reply: @escaping (Bool, String?) -> Void)
    /// Turns the enforcing parts on/off: the pf anchor and the DNS proxy.
    /// Off by default — PureSnitch observes until the user opts in.
    func setEnforcementEnabled(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void)
    func stopMonitoring(reply: @escaping (Bool, String?) -> Void)
    func currentConnections(reply: @escaping (Data) -> Void)
    func currentTrafficSample(reply: @escaping (Data) -> Void)

    func enableBlocklist(idString: String, enabled: Bool, reply: @escaping (Bool, String?) -> Void)
    func refreshBlocklists(reply: @escaping (Bool, String?) -> Void)
    func setDoHUpstream(url: String, reply: @escaping (Bool, String?) -> Void)

    func installPF(reply: @escaping (Bool, String?) -> Void)
    func uninstallPF(reply: @escaping (Bool, String?) -> Void)
    func flushAll(reply: @escaping (Bool, String?) -> Void)

    func recentBlocked(limit: Int, reply: @escaping (Data) -> Void)
    func recentDenied(limit: Int, reply: @escaping (Data) -> Void)
}

@objc public protocol HelperClientProtocol {
    func notifyConnection(connectionJSON: Data)
    func notifyTraffic(sampleJSON: Data)
    func notifyAlert(connectionJSON: Data, reply: @escaping (Bool, Bool) -> Void)
    func notifyLog(level: String, message: String)
}

public enum HelperBridge {
    public static let machServiceName = AppConstants.xpcMachServiceName

    public static func remoteInterface() -> NSXPCInterface {
        let iface = NSXPCInterface(with: HelperProtocol.self)
        return iface
    }
    public static func exportedInterface() -> NSXPCInterface {
        let iface = NSXPCInterface(with: HelperClientProtocol.self)
        return iface
    }
}
