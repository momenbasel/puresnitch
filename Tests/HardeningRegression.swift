import Darwin
import Foundation
import Network
import SQLite3

private struct RegressionFailure: Error, CustomStringConvertible {
    let description: String
}

private func require(
    _ condition: @autoclosure () -> Bool,
    _ message: String,
    file: StaticString = #filePath,
    line: UInt = #line
) throws {
    guard condition() else {
        throw RegressionFailure(description: "\(file):\(line): \(message)")
    }
}

private func requireThrows(
    _ message: String,
    _ body: () throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) throws {
    do {
        try body()
        throw RegressionFailure(description: "\(file):\(line): \(message)")
    } catch is RegressionFailure {
        throw RegressionFailure(description: "\(file):\(line): \(message)")
    } catch {
        return
    }
}

private func withContext<T>(_ context: String, _ body: () throws -> T) throws -> T {
    do {
        return try body()
    } catch {
        throw RegressionFailure(description: "\(context): \(error)")
    }
}

private final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = 0

    func increment() {
        lock.lock()
        storage += 1
        lock.unlock()
    }

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

private final class LockedBool: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: Bool?

    func setIfUnset(_ value: Bool) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard storage == nil else { return false }
        storage = value
        return true
    }

    var value: Bool? {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

private struct CommandInvocation: Equatable {
    let executable: String
    let arguments: [String]
}

private final class FakePFRunner: @unchecked Sendable {
    private let lock = NSLock()
    private var invocationsStorage: [CommandInvocation] = []
    private var failingArgumentsStorage: [String]?
    private var parentAnchorActiveStorage = true
    private var referencesContainTokenStorage = true
    private let enableToken = "424242"

    var parentAnchorActive: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return parentAnchorActiveStorage
        }
        set {
            lock.lock()
            parentAnchorActiveStorage = newValue
            lock.unlock()
        }
    }

    var failingArguments: [String]? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return failingArgumentsStorage
        }
        set {
            lock.lock()
            failingArgumentsStorage = newValue
            lock.unlock()
        }
    }

    var referencesContainToken: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return referencesContainTokenStorage
        }
        set {
            lock.lock()
            referencesContainTokenStorage = newValue
            lock.unlock()
        }
    }

    var invocations: [CommandInvocation] {
        lock.lock()
        defer { lock.unlock() }
        return invocationsStorage
    }

    func run(executable: String, arguments: [String]) throws -> String {
        lock.lock()
        invocationsStorage.append(CommandInvocation(executable: executable, arguments: arguments))
        let shouldFail = failingArgumentsStorage == arguments
        let parentAnchorActive = parentAnchorActiveStorage
        let referencesContainToken = referencesContainTokenStorage
        lock.unlock()

        if shouldFail {
            throw NSError(
                domain: "FakePFRunner",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "injected command failure"]
            )
        }
        switch arguments {
        case ["-sr"]:
            return parentAnchorActive ? "anchor \"com.apple/*\"\n" : "block drop all\n"
        case ["-E"]:
            return "pf enabled\nToken : \(enableToken)\n"
        case ["-s", "References"]:
            return referencesContainToken ? "0 PureSnitch \(enableToken)\n" : "0 other 999999\n"
        default:
            return ""
        }
    }
}

private final class ListenerGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var result: Result<Void, Error>?

    func update(_ state: NWListener.State) {
        switch state {
        case .ready:
            finish(.success(()))
        case .failed(let error):
            finish(.failure(error))
        case .cancelled:
            finish(.failure(RegressionFailure(description: "listener cancelled before ready")))
        default:
            break
        }
    }

    func wait(seconds: TimeInterval) throws {
        condition.lock()
        defer { condition.unlock() }
        let deadline = Date().addingTimeInterval(seconds)
        while result == nil && condition.wait(until: deadline) {}
        guard let result else {
            throw RegressionFailure(description: "listener did not become ready within \(seconds) seconds")
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

private func testRuleValidationAndMatching() throws {
    let validHosts = [
        "example.com",
        ".example.com",
        "*.example.com",
        "127.0.0.1",
        "192.0.2.0/24",
    ]
    for host in validHosts {
        try Rule(remoteHost: host, action: .deny).validateForPersistence()
    }

    let validIPs = ["0.0.0.0/0", "192.0.2.1", "255.255.255.255/32"]
    for ip in validIPs {
        try Rule(remoteIP: ip, action: .deny).validateForPersistence()
    }
    try Rule(remotePort: 0, action: .deny).validateForPersistence()
    try Rule(remotePort: 65_535, action: .deny).validateForPersistence()

    let invalidEndpoints = [
        "example.com\nblock out all",
        "example.com\tpass all",
        " example.com",
        "example.com ",
        "example.com#comment",
        "example.com{evil}",
        "example.com,evil",
        "example.com to any",
        "exämple.com",
        "01.2.3.4",
        "256.2.3.4",
        "192.0.2.0/-1",
        "192.0.2.0/33",
        "192.0.2.0/999999",
    ]
    for endpoint in invalidEndpoints {
        try requireThrows("remote host accepted unsafe endpoint \(endpoint.debugDescription)") {
            try Rule(remoteHost: endpoint, action: .deny).validateForPersistence()
        }
        try requireThrows("remote IP accepted unsafe endpoint \(endpoint.debugDescription)") {
            try Rule(remoteIP: endpoint, action: .deny).validateForPersistence()
        }
    }
    for port in [-1, 65_536] {
        try requireThrows("remote port \(port) should be rejected") {
            try Rule(remotePort: port, action: .deny).validateForPersistence()
        }
    }

    let matcher = RuleMatcher()
    let invalidCIDRs = [
        "192.0.2.0/-1",
        "192.0.2.0/33",
        "192.0.2.0/\(Int.min)",
    ]
    for cidr in invalidCIDRs {
        try require(!matcher.ipMatches(pattern: cidr, ip: "192.0.2.1"), "invalid CIDR matched: \(cidr)")
    }
    try require(matcher.ipMatches(pattern: "0.0.0.0/0", ip: "203.0.113.42"), "/0 should match")
    try require(matcher.ipMatches(pattern: "192.0.2.1/32", ip: "192.0.2.1"), "/32 exact match failed")
    try require(!matcher.ipMatches(pattern: "192.0.2.1/32", ip: "192.0.2.2"), "/32 overmatched")

    try require(matcher.hostMatches(pattern: ".example.com", host: "example.com"), "leading-dot apex did not match")
    try require(matcher.hostMatches(pattern: ".example.com", host: "api.example.com"), "leading-dot child did not match")
    try require(!matcher.hostMatches(pattern: ".example.com", host: "evil-example.com"), "leading-dot crossed label boundary")
    try require(!matcher.hostMatches(pattern: ".example.com", host: "example.com.evil"), "leading-dot matched suffix extension")
}

private func testHelperStatusCompatibility() throws {
    let status = HelperStatus(
        version: "0.2.1",
        mode: .silentDeny,
        enforcementDesired: true,
        legacyPFMigrationPending: true,
        legacyPFReconciliationSucceeded: true,
        running: true,
        pfctlActive: true,
        dnsProxyActive: true,
        dnsProxyPort: 53,
        activeRules: 7,
        blockedToday: 3
    )
    let roundTrip = try JSONDecoder().decode(HelperStatus.self, from: JSONEncoder().encode(status))
    try require(roundTrip.mode == .silentDeny, "HelperStatus mode was lost during Codable round-trip")
    try require(roundTrip.enforcementDesired, "helper-authoritative enforcement intent was lost during Codable round-trip")
    try require(roundTrip.legacyPFMigrationPending, "legacy PF migration intent was lost during Codable round-trip")
    try require(
        roundTrip.legacyPFReconciliationSucceeded,
        "legacy PF reconciliation health was lost during Codable round-trip"
    )
    try require(roundTrip.version == status.version, "HelperStatus version changed during round-trip")
    try require(roundTrip.pfctlActive && roundTrip.dnsProxyActive, "HelperStatus enforcement flags changed")

    let legacyJSON = Data(
        """
        {
          "version": "0.2.0",
          "running": true,
          "pfctlActive": false,
          "dnsProxyActive": false,
          "dnsProxyPort": 53,
          "activeRules": 2,
          "blockedToday": 1
        }
        """.utf8
    )
    let legacy = try JSONDecoder().decode(HelperStatus.self, from: legacyJSON)
    try require(legacy.mode == .alert, "legacy HelperStatus should default mode to alert")
    try require(!legacy.enforcementDesired, "legacy HelperStatus should default enforcement intent to false")
    try require(!legacy.legacyPFMigrationPending, "legacy HelperStatus should default PF migration intent to false")
    try require(
        !legacy.legacyPFReconciliationSucceeded,
        "legacy HelperStatus should default PF reconciliation health to false"
    )
}

private func testHelperSecurityState() throws {
    try require(
        HelperSecurityState.legacyPFMigrationPendingSettingKey == "legacy_pf_migration_pending",
        "legacy PF migration setting key changed"
    )
    try require(
        HelperSecurityState.legacyPFReconciliationSettingKey == "legacy_pf_reconciliation_succeeded",
        "legacy PF reconciliation setting key changed"
    )
    let missingDesired = try HelperSecurityState.decodeDesired(nil)
    let emptyDesired = try HelperSecurityState.decodeDesired("")
    let disabledDesired = try HelperSecurityState.decodeDesired("0")
    let enabledDesired = try HelperSecurityState.decodeDesired("1")
    try require(!missingDesired, "missing desired state should restore disabled")
    try require(!emptyDesired, "empty desired state should restore disabled")
    try require(!disabledDesired, "encoded disabled state restored enabled")
    try require(enabledDesired, "encoded enabled state did not restore")
    try require(HelperSecurityState.encodeDesired(true) == "1", "enabled state encoding changed")
    try require(HelperSecurityState.encodeDesired(false) == "0", "disabled state encoding changed")
    for invalid in ["true", "01", "-1", "2"] {
        try requireThrows("invalid desired state \(invalid) should fail closed") {
            _ = try HelperSecurityState.decodeDesired(invalid)
        }
    }

    let missingOwner = try HelperSecurityState.decodeOwnerUID(nil)
    let decodedOwner = try HelperSecurityState.decodeOwnerUID("501")
    let encodedOwner = try HelperSecurityState.encodeOwnerUID(501)
    try require(missingOwner == nil, "missing owner should remain unclaimed")
    try require(decodedOwner == 501, "owner UID did not decode")
    try require(encodedOwner == "501", "owner UID did not encode canonically")
    for invalid in ["0", "0501", "-1", "root"] {
        try requireThrows("invalid owner UID \(invalid) was accepted") {
            _ = try HelperSecurityState.decodeOwnerUID(invalid)
        }
    }
    try requireThrows("root must not be persisted as the desktop owner") {
        _ = try HelperSecurityState.encodeOwnerUID(0)
    }

    try require(
        HelperAuthorizationPolicy.allows(peerUID: 501, consoleUID: 501, peerIsAdmin: true),
        "active non-root console administrator could not claim an unowned helper"
    )
    try require(
        !HelperAuthorizationPolicy.allows(peerUID: 0, consoleUID: 0, peerIsAdmin: true),
        "root peer was allowed to claim the desktop helper"
    )
    try require(
        !HelperAuthorizationPolicy.allows(peerUID: 502, consoleUID: 501, peerIsAdmin: true),
        "non-console peer was allowed to claim the helper"
    )
    try require(
        !HelperAuthorizationPolicy.allows(peerUID: 501, consoleUID: nil, peerIsAdmin: true),
        "peer was allowed when no console owner was available"
    )
    try require(
        !HelperAuthorizationPolicy.allows(peerUID: 501, consoleUID: 501, peerIsAdmin: false),
        "non-admin console peer was allowed to claim the helper"
    )
    try require(
        HelperAuthorizationPolicy.allows(
            peerUID: 501,
            persistedOwnerUID: 501,
            consoleUID: 502,
            peerIsAdmin: true
        ),
        "persisted administrator lost access after console user changed"
    )
    try require(
        !HelperAuthorizationPolicy.allows(
            peerUID: 501,
            persistedOwnerUID: 501,
            consoleUID: 501,
            peerIsAdmin: false
        ),
        "demoted persisted owner retained helper mutation access"
    )
    try require(
        !HelperAuthorizationPolicy.allows(
            peerUID: 502,
            persistedOwnerUID: 501,
            consoleUID: 502,
            peerIsAdmin: true
        ),
        "non-owner UID was allowed to mutate claimed helper state"
    )
    try require(
        !HelperAuthorizationPolicy.allows(
            peerUID: 502,
            persistedOwnerUID: 501,
            persistedOwnerIsAdmin: true,
            consoleUID: 502,
            peerIsAdmin: true
        ),
        "active console admin displaced a persisted owner who remains an admin"
    )
    try require(
        HelperAuthorizationPolicy.allows(
            peerUID: 502,
            persistedOwnerUID: 501,
            persistedOwnerIsAdmin: false,
            consoleUID: 502,
            peerIsAdmin: true
        ),
        "active console admin could not recover a helper from a demoted owner"
    )
    try require(
        !HelperAuthorizationPolicy.allows(
            peerUID: 503,
            persistedOwnerUID: 501,
            persistedOwnerIsAdmin: false,
            consoleUID: 502,
            peerIsAdmin: true
        ),
        "off-console administrator recovered a helper from a demoted owner"
    )
    try require(
        !HelperAuthorizationPolicy.allows(
            peerUID: 501,
            persistedOwnerUID: 501,
            persistedOwnerIsAdmin: false,
            consoleUID: 501,
            peerIsAdmin: false
        ),
        "demoted old owner retained access during recovery"
    )
    try require(
        HelperAuthorizationPolicy.allowsExistingClient(
            peerUID: 501,
            ownerUID: 501,
            peerIsAdmin: true
        ),
        "current administrator owner was rejected during per-call revalidation"
    )
    try require(
        !HelperAuthorizationPolicy.allowsExistingClient(
            peerUID: 501,
            ownerUID: 501,
            peerIsAdmin: false
        ),
        "demoted owner retained an existing helper connection"
    )
    try require(
        !HelperAuthorizationPolicy.allowsExistingClient(
            peerUID: 502,
            ownerUID: 501,
            peerIsAdmin: true
        ),
        "non-owner administrator passed existing-client revalidation"
    )
    try require(
        !HelperAuthorizationPolicy.allowsExistingClient(
            peerUID: 0,
            ownerUID: 0,
            peerIsAdmin: true
        ),
        "root passed desktop existing-client revalidation"
    )
    try require(
        !HelperAuthorizationPolicy.allowsExistingClient(
            peerUID: 501,
            ownerUID: nil,
            peerIsAdmin: true
        ),
        "existing client was authorized without a claimed owner"
    )

    try withTemporaryDirectory { directory in
        let supportURL = directory.appendingPathComponent("support", isDirectory: true)
        let ownerUID = geteuid()
        try HelperSecurityState.prepareSupportDirectory(at: supportURL.path, expectedOwnerUID: ownerUID)
        let supportPermissions = try filePermissions(at: supportURL.path)
        try require(supportPermissions == 0o700, "helper support directory was not mode 0700")

        let databaseURL = supportURL.appendingPathComponent("puresnitch.sqlite")
        do {
            let store = try RuleStore(path: databaseURL.path)
            try store.setSetting(
                HelperSecurityState.desiredSettingKey,
                HelperSecurityState.encodeDesired(true)
            )
            try HelperSecurityState.hardenDatabaseFiles(databaseURL.path, expectedOwnerUID: ownerUID)
            for path in [databaseURL.path, databaseURL.path + "-wal", databaseURL.path + "-shm"] {
                try require(FileManager.default.fileExists(atPath: path), "SQLite security fixture was not created: \(path)")
                let permissions = try filePermissions(at: path)
                try require(permissions == 0o600, "helper database file was not mode 0600: \(path)")
            }
        }

        try HelperSecurityState.validateDatabasePathBeforeOpen(databaseURL.path, expectedOwnerUID: ownerUID)
        do {
            let restartedStore = try RuleStore(path: databaseURL.path)
            let restored = try HelperSecurityState.decodeDesired(
                restartedStore.getSetting(HelperSecurityState.desiredSettingKey)
            )
            try require(restored, "helper restart did not restore persisted desired enforcement")
            try restartedStore.setSetting(
                HelperSecurityState.desiredSettingKey,
                HelperSecurityState.encodeDesired(false)
            )
            try HelperSecurityState.hardenDatabaseFiles(databaseURL.path, expectedOwnerUID: ownerUID)
        }
        let disabledRestart = try RuleStore(path: databaseURL.path)
        let restoredDisabled = try HelperSecurityState.decodeDesired(
            disabledRestart.getSetting(HelperSecurityState.desiredSettingKey)
        )
        try require(
            !restoredDisabled,
            "persisted disabled enforcement restored enabled"
        )

        let wrongOwner = ownerUID == uid_t.max ? ownerUID - 1 : ownerUID + 1
        try requireThrows("database owned by another UID passed pre-open validation") {
            try HelperSecurityState.validateDatabasePathBeforeOpen(databaseURL.path, expectedOwnerUID: wrongOwner)
        }

        let targetURL = supportURL.appendingPathComponent("target.sqlite")
        let symlinkURL = supportURL.appendingPathComponent("linked.sqlite")
        try Data().write(to: targetURL)
        try FileManager.default.createSymbolicLink(at: symlinkURL, withDestinationURL: targetURL)
        try requireThrows("symlink database path passed pre-open validation") {
            try HelperSecurityState.validateDatabasePathBeforeOpen(symlinkURL.path, expectedOwnerUID: ownerUID)
        }

        let danglingTargetURL = supportURL.appendingPathComponent("missing-target.sqlite")
        let danglingSymlinkURL = supportURL.appendingPathComponent("dangling.sqlite")
        try FileManager.default.createSymbolicLink(
            at: danglingSymlinkURL,
            withDestinationURL: danglingTargetURL
        )
        try requireThrows("dangling database symlink passed pre-open validation") {
            try HelperSecurityState.validateDatabasePathBeforeOpen(
                danglingSymlinkURL.path,
                expectedOwnerUID: ownerUID
            )
        }
        try requireThrows("dangling database symlink passed file hardening") {
            try HelperSecurityState.hardenDatabaseFiles(
                danglingSymlinkURL.path,
                expectedOwnerUID: ownerUID
            )
        }
    }
}

private func testHelperServiceAuthorizationIntegration() throws {
    guard let repositoryPath = ProcessInfo.processInfo.environment["PURESNITCH_REPO_DIR"],
          !repositoryPath.isEmpty else {
        throw RegressionFailure(description: "PURESNITCH_REPO_DIR was not provided")
    }
    let helperServicePath = URL(fileURLWithPath: repositoryPath)
        .appendingPathComponent("Sources/Helper/HelperService.swift")
    let source = try String(contentsOf: helperServicePath, encoding: .utf8)

    func section(from startMarker: String, to endMarker: String) throws -> String {
        guard let start = source.range(of: startMarker) else {
            throw RegressionFailure(description: "HelperService integration marker is missing: \(startMarker)")
        }
        let remainder = source[start.lowerBound...]
        guard let end = remainder.range(of: endMarker) else {
            throw RegressionFailure(description: "HelperService integration marker is missing: \(endMarker)")
        }
        return String(remainder[..<end.lowerBound])
    }

    let broadcast = try section(
        from: "private func broadcast(",
        to: "private func handleDNSAsk("
    )
    try require(
        broadcast.contains("guard isAuthorizedExistingClient(conn) else"),
        "outbound client broadcasts are not revalidated against the current owner/admin state"
    )

    let ask = try section(
        from: "private func handleDNSAsk(",
        to: "private func settlePendingAsk("
    )
    try require(
        ask.contains("guard self.isAuthorizedExistingClient(connection) else"),
        "DNS alert replies are accepted without current owner/admin revalidation"
    )

    let authorization = try section(
        from: "private func isAuthorizedExistingClient(",
        to: "private func revokeAllClientConnectionsAfterOwnerChange("
    )
    try require(
        authorization.contains("HelperAuthorizationPolicy.allowsExistingClient("),
        "HelperService existing-client guard bypasses the tested authorization policy"
    )
}

private func testLegacyHelperUpgradeSequencing() throws {
    guard let repositoryPath = ProcessInfo.processInfo.environment["PURESNITCH_REPO_DIR"],
          !repositoryPath.isEmpty else {
        throw RegressionFailure(description: "PURESNITCH_REPO_DIR was not provided")
    }
    let helperClientPath = URL(fileURLWithPath: repositoryPath)
        .appendingPathComponent("Sources/GUI/App/HelperClient.swift")
    let source = try String(contentsOf: helperClientPath, encoding: .utf8)
    let settingsSource = try String(
        contentsOf: URL(fileURLWithPath: repositoryPath)
            .appendingPathComponent("Sources/GUI/Views/SettingsView.swift"),
        encoding: .utf8
    )

    func section(from startMarker: String, to endMarker: String) throws -> String {
        guard let start = source.range(of: startMarker) else {
            throw RegressionFailure(description: "HelperClient integration marker is missing: \(startMarker)")
        }
        let remainder = source[start.lowerBound...]
        guard let end = remainder.range(of: endMarker) else {
            throw RegressionFailure(description: "HelperClient integration marker is missing: \(endMarker)")
        }
        return String(remainder[..<end.lowerBound])
    }

    let versionGate = try section(
        from: "private static func isLegacyHelperVersion(",
        to: "private static let maximumLegacyMigrationAttempts"
    )
    try require(
        versionGate.contains("version == \"0.1.0\"")
            && versionGate.contains("version == \"0.2.0\""),
        "legacy helper gate does not cover both v0.1.0 and v0.2.0"
    )

    let unregister = try section(from: "func unregisterDaemon()", to: "func repairHelper()")
    guard let legacyBlock = unregister.range(
        of: "guard !Self.isLegacyHelperVersion(self.helperVersionBeforeUnregistration)"
    ), let pendingMigrationBlock = unregister.range(
        of: "!self.helperHadPendingLegacyMigrationBeforeUnregistration else"
    ), let directRemoval = unregister.range(of: "service.unregister") else {
        throw RegressionFailure(description: "direct legacy removal guard is missing")
    }
    try require(
        legacyBlock.lowerBound < directRemoval.lowerBound
            && pendingMigrationBlock.lowerBound < directRemoval.lowerBound,
        "direct unregister reaches launchd before blocking legacy or pending-migration helpers"
    )
    try require(
        unregister.contains("only be removed through Repair Helper"),
        "direct legacy removal no longer directs the user through checked repair"
    )
    try require(
        settingsSource.contains("Button(\"Remove Helper…\", role: .destructive)")
            && settingsSource.contains("state.helper.unregisterDaemon()")
            && settingsSource.contains(".disabled(removeHelperDisabled)"),
        "signed app does not expose a confirmed, gated helper-removal path"
    )
    guard let removeGateStart = settingsSource.range(of: "private var removeHelperDisabled: Bool") else {
        throw RegressionFailure(description: "helper removal runtime gate is missing")
    }
    let removeGate = settingsSource[removeGateStart.lowerBound...]
    for requiredState in [
        "state.helperConnected",
        "state.helperStatusLoaded",
        "state.enforcementEnabled",
        "state.pfctlEnabled",
        "state.dnsProxyEnabled",
        "state.enforcementRequestInFlight",
    ] {
        try require(
            removeGate.contains(requiredState),
            "helper removal gate does not require safe state: \(requiredState)"
        )
    }

    let repair = try section(
        from: "func repairHelper()",
        to: "private func prepareHelperForUnregistration("
    )
    try require(
        repair.contains("let replacedLegacyVersion = Self.isLegacyHelperVersion(")
            && repair.contains("service.unregister")
            && repair.contains("try replacementService.register()"),
        "Repair Helper no longer performs checked legacy replacement"
    )

    let preparation = try section(
        from: "private func prepareHelperForUnregistration(",
        to: "private func finishHelperShutdownPreparation("
    )
    try require(
        preparation.contains("if status.pfctlActive")
            && preparation.contains("self.capturedLegacyEnforcementIntent = true"),
        "legacy enforcement intent is not captured only from observed PF activity"
    )
    try require(
        preparation.contains("if Self.isLegacyHelperVersion(status.version)")
            && preparation.contains("self.finishHelperShutdownPreparation("),
        "legacy v0.1.0/v0.2.0 status does not preserve PF for replacement reconciliation"
    )
    for forbidden in [
        "proxy.uninstallPF",
        "proxy.reloadRules",
        "proxy.stopMonitoring",
        "proxy.startMonitoring",
        "proxy.installPF",
        "proxy.setEnforcementEnabled",
    ] {
        try require(
            !preparation.contains(forbidden),
            "old-helper legacy preparation contains forbidden mutation \(forbidden)"
        )
    }

    let finishCleanup = try section(
        from: "private func finishHelperShutdownPreparation(",
        to: "private func recoverRuntimeAfterFailedUnregistration()"
    )
    try require(
        finishCleanup.contains("if !Self.isLegacyHelperVersion(helperVersionBeforeUnregistration)")
            && finishCleanup.contains("state?.pfctlEnabled = false")
            && finishCleanup.contains("state?.dnsProxyEnabled = false"),
        "legacy replacement preparation falsely reports preserved runtime as stopped"
    )

    let inspection = try section(
        from: "private func inspectCurrentHelperForLegacyUpgrade(",
        to: "private func promptForLegacyEnforcementDecision("
    )
    try require(
        inspection.contains("if helperStatus.legacyPFMigrationPending")
            && inspection.contains("if let explicitChoice = self.explicitLegacyEnforcementChoice")
            && inspection.contains("enabled: explicitChoice"),
        "replacement helper does not limit automatic retry to an explicit signed-app choice"
    )
    try require(
        inspection.contains("self.promptForLegacyEnforcementDecision("),
        "unknown migration state does not require an explicit user decision"
    )
    try require(
        !inspection.contains("enabled: trustedIntent")
            && !inspection.contains("?? (helperStatus.enforcementDesired ? true : nil)"),
        "captured or root-owned intent can still authorize automatic ruleset replacement"
    )
    guard let explicitRetry = inspection.range(
        of: "if let explicitChoice = self.explicitLegacyEnforcementChoice"
    ), let deferredGate = inspection.range(
        of: "} else if !self.legacyDecisionDeferred {"
    ), let explicitPrompt = inspection.range(
        of: "self.promptForLegacyEnforcementDecision("
    ) else {
        throw RegressionFailure(description: "explicit-choice/deferred migration gate is missing")
    }
    try require(
        explicitRetry.lowerBound < deferredGate.lowerBound
            && deferredGate.lowerBound < explicitPrompt.lowerBound,
        "Decide Later does not dominate captured/root intent on reconnect"
    )
    guard let resumedExplicitChoice = inspection.range(
        of: "if self.explicitLegacyEnforcementChoice == true"
    ) else {
        throw RegressionFailure(description: "resumed explicit-choice migration path is missing")
    }
    let resumedMigration = inspection[resumedExplicitChoice.lowerBound...]
    try require(
        resumedMigration.contains("self.finalizeLegacyUpgrade("),
        "an explicitly confirmed migration cannot resume after a lost reply"
    )

    let prompt = try section(
        from: "private func promptForLegacyEnforcementDecision(",
        to: "private func finalizeLegacyUpgrade("
    )
    try require(
        prompt.contains("Keep Enforcement On")
            && prompt.contains("Turn Enforcement Off")
            && prompt.contains("Decide Later"),
        "legacy migration prompt does not offer explicit on/off/defer choices"
    )
    guard let decideLaterButton = prompt.range(of: "addButton(withTitle: \"Decide Later\")"),
          let keepOnButton = prompt.range(of: "addButton(withTitle: \"Keep Enforcement On with Current Rules\")") else {
        throw RegressionFailure(description: "legacy migration button ordering is missing")
    }
    try require(
        decideLaterButton.lowerBound < keepOnButton.lowerBound,
        "legacy migration does not default to the non-mutating Decide Later choice"
    )
    try require(
        prompt.contains("Homebrew recovery snapshots are not imported automatically")
            && prompt.contains("Decide Later is the only choice that preserves the legacy firewall rules unchanged"),
        "legacy migration prompt does not disclose the recovery-only Homebrew snapshot"
    )
    try require(
        prompt.contains("let hasCurrentRules = initialStatus.activeRules > 0")
            && prompt.contains("keepOnButton.isEnabled = hasCurrentRules")
            && prompt.contains("guard hasCurrentRules else")
            && prompt.contains("explicitLegacyEnforcementChoice = true")
            && prompt.contains("explicitLegacyEnforcementChoice = false"),
        "empty replacement rule stores can still discard legacy rules through Keep On"
    )
    try require(
        prompt.contains("non-default, allow, process-only, domain-only, disabled, expired")
            && prompt.contains("will not survive as host-wide PF rules"),
        "legacy prompt does not disclose the narrower current PF ruleset semantics"
    )
    guard let responseSwitch = prompt.range(of: "switch response"),
          let finalize = prompt.range(of: "finalizeLegacyUpgrade(") else {
        throw RegressionFailure(description: "legacy migration choice handling is missing")
    }
    try require(
        responseSwitch.lowerBound < finalize.lowerBound,
        "legacy migration mutates privileged state before the user's choice"
    )

    let finalization = try section(
        from: "private func finalizeLegacyUpgrade(",
        to: "private func finishLegacyUpgradeFinalization("
    )
    try require(
        finalization.contains("proxy.setEnforcementEnabled(enabled)")
            && finalization.contains("confirmedStatus?.legacyPFMigrationPending == false")
            && finalization.contains("confirmedStatus?.legacyPFReconciliationSucceeded == true"),
        "legacy finalization does not require current-helper reconciliation confirmation"
    )
    guard let emptyStoreDefense = finalization.range(
        of: "guard !enabled || initialStatus.activeRules > 0 else"
    ), let privilegedEnable = finalization.range(
        of: "proxy.setEnforcementEnabled(enabled)"
    ) else {
        throw RegressionFailure(description: "empty-store finalization defense is missing")
    }
    try require(
        emptyStoreDefense.lowerBound < privilegedEnable.lowerBound
            && finalization.contains("legacyDecisionDeferred = true")
            && finalization.contains("guard explicitLegacyEnforcementChoice == enabled else"),
        "enabled legacy finalization can mutate PF before rejecting an empty current rule store"
    )
    try require(
        !source.contains("UserDefaults.standard") && !source.contains("PSLegacy"),
        "per-user legacy state can trigger privileged migration"
    )
}

private func testHelperClientRecoveryAndStatusFreshness() throws {
    guard let repositoryPath = ProcessInfo.processInfo.environment["PURESNITCH_REPO_DIR"],
          !repositoryPath.isEmpty else {
        throw RegressionFailure(description: "PURESNITCH_REPO_DIR was not provided")
    }
    let repositoryURL = URL(fileURLWithPath: repositoryPath)
    let source = try String(
        contentsOf: repositoryURL.appendingPathComponent("Sources/GUI/App/HelperClient.swift"),
        encoding: .utf8
    )

    func section(from startMarker: String, to endMarker: String) throws -> String {
        guard let start = source.range(of: startMarker) else {
            throw RegressionFailure(description: "HelperClient integration marker is missing: \(startMarker)")
        }
        let remainder = source[start.lowerBound...]
        guard let end = remainder.range(of: endMarker) else {
            throw RegressionFailure(description: "HelperClient integration marker is missing: \(endMarker)")
        }
        return String(remainder[..<end.lowerBound])
    }

    let falseWrites = source.components(
        separatedBy: "shouldRestoreEnforcementAfterFailedUnregistration = false"
    ).count - 1
    try require(
        falseWrites == 2,
        "interrupted-cleanup intent is cleared outside its declaration and authoritative resolver"
    )

    let preparation = try section(
        from: "private func prepareHelperForUnregistration(",
        to: "private func finishHelperShutdownPreparation("
    )
    try require(
        preparation.contains("status.version == AppConstants.version && !status.enforcementDesired")
            && preparation.contains("clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution()")
            && preparation.contains("status.enforcementDesired && runtimeWasActive")
            && preparation.contains("armInterruptedUnregistrationRecovery()"),
        "shutdown preparation does not distinguish authoritative off from interrupted desired-on cleanup"
    )
    guard let migrationPending = preparation.range(of: "if status.legacyPFMigrationPending"),
          let recoveryArm = preparation.range(of: "armInterruptedUnregistrationRecovery()") else {
        throw RegressionFailure(description: "shutdown migration/recovery ordering markers are missing")
    }
    try require(
        migrationPending.lowerBound < recoveryArm.lowerBound,
        "migration-pending shutdown can arm automatic enforcement recovery"
    )

    let finishPreparation = try section(
        from: "private func finishHelperShutdownPreparation(",
        to: "private func recoverRuntimeAfterFailedUnregistration()"
    )
    try require(
        finishPreparation.contains("let preparationSucceeded = ready && isCurrentConnection")
            && finishPreparation.contains("completion(preparationSucceeded)")
            && finishPreparation.contains("shouldRestoreEnforcementAfterFailedUnregistration")
            && finishPreparation.contains("DispatchQueue.main.async")
            && finishPreparation.contains("self?.refreshStatus()"),
        "cleanup success is trusted after connection invalidation or failure does not retain reconciliation intent"
    )
    try require(
        !finishPreparation.contains("clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution")
            && !finishPreparation.contains("setEnforcementEnabled(true)"),
        "cleanup reply directly clears or restores retained enforcement intent"
    )

    let failedUnregisterRecovery = try section(
        from: "private func recoverRuntimeAfterFailedUnregistration()",
        to: "private func inspectCurrentHelperForLegacyUpgrade("
    )
    try require(
        failedUnregisterRecovery.contains("if shouldRestoreEnforcementAfterFailedUnregistration")
            && failedUnregisterRecovery.contains("refreshStatus()")
            && !failedUnregisterRecovery.contains("setEnforcementEnabled(true)")
            && !failedUnregisterRecovery.contains("clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution"),
        "failed unregister does not preserve intent until authenticated status reconciliation"
    )

    let unavailable = try section(
        from: "private func markStatusUnavailable(",
        to: "private func cancelInterruptedRecoveryAttemptForConnectionChange("
    )
    for requiredMarker in [
        "status = nil",
        "state?.helperStatusLoaded = false",
        "state?.pfctlEnabled = false",
        "state?.dnsProxyEnabled = false",
        "needsRepair = true",
    ] {
        try require(
            unavailable.contains(requiredMarker),
            "unavailable status retains trusted-looking UI state: \(requiredMarker)"
        )
    }

    let connectionLoss = try section(
        from: "private func markConnectionUnavailable(",
        to: "private func setConnected("
    )
    try require(
        connectionLoss.contains("cancelInterruptedRecoveryAttemptForConnectionChange()")
            && connectionLoss.contains("markStatusUnavailable(nil)")
            && !connectionLoss.contains("clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution"),
        "connection loss clears durable recovery intent or leaves stale status visible"
    )

    let polling = try section(
        from: "private func startPolling()",
        to: "private func reconnectAndPing()"
    )
    try require(
        polling.contains("guard !self.connected else")
            && polling.contains("self.refreshStatus()")
            && !polling.contains("self.needsRepair = false"),
        "connected polling trusts XPC connectivity instead of refreshing helper status"
    )

    let statusRequest = try section(
        from: "private func refreshStatus()",
        to: "private func finishStatusRequest("
    )
    for requiredMarker in [
        "!isRepairing",
        "pendingEnforcementRequestGeneration == nil",
        "pendingModeRequestGeneration == nil",
        "pendingInterruptedRecoveryRequestGeneration == nil",
        "pendingStatusRequestGeneration == nil",
        "pendingStatusRequestGeneration = generation",
        "Self.statusRequestTimeout",
        "proxy.getStatus",
        "helperStatus?.version == AppConstants.version",
    ] {
        try require(
            statusRequest.contains(requiredMarker),
            "status polling lost coalescing, mutation, timeout, or authentication guard: \(requiredMarker)"
        )
    }

    let statusSettlement = try section(
        from: "private func finishStatusRequest(",
        to: "private func acceptAuthenticatedCurrentStatus("
    )
    try require(
        statusSettlement.contains("pendingStatusRequestGeneration == generation")
            && statusSettlement.contains("markStatusUnavailable(failureMessage)")
            && statusSettlement.contains("acceptAuthenticatedCurrentStatus("),
        "status timeout/error can retain stale state or bypass current-request settlement"
    )

    let acceptedStatus = try section(
        from: "private func acceptAuthenticatedCurrentStatus(",
        to: "private func beginInterruptedUnregistrationRecovery("
    )
    try require(
        acceptedStatus.contains("let runtimeMatchesDesired = helperStatus.enforcementDesired")
            && acceptedStatus.contains("needsRepair = !runtimeMatchesDesired")
            && acceptedStatus.contains("status = helperStatus"),
        "authenticated asynchronous status does not derive degraded UI state from desired/runtime mismatch"
    )
    try require(
        acceptedStatus.contains("if !helperStatus.enforcementDesired")
            && acceptedStatus.contains("helperStatus.pfctlActive && helperStatus.dnsProxyActive")
            && acceptedStatus.contains("clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution()"),
        "retained cleanup intent lacks authoritative desired-off/runtime-restored clearing rules"
    )
    try require(
        acceptedStatus.contains("!helperStatus.legacyPFMigrationPending")
            && acceptedStatus.contains("armInterruptedUnregistrationRecovery()")
            && acceptedStatus.contains("beginInterruptedUnregistrationRecovery("),
        "migration-pending status can trigger automatic enforcement recovery"
    )
    try require(
        acceptedStatus.contains("helperStatus.enforcementDesired")
            && acceptedStatus.contains("!runtimeMatchesDesired")
            && acceptedStatus.contains("!shouldRestoreEnforcementAfterFailedUnregistration"),
        "a fresh GUI cannot re-arm recovery from authenticated current-helper desired/runtime mismatch"
    )

    let interruptedRecovery = try section(
        from: "private func beginInterruptedUnregistrationRecovery(",
        to: "private func finishInterruptedUnregistrationRecovery("
    )
    for requiredMarker in [
        "!helperStatus.legacyPFMigrationPending",
        "pendingInterruptedRecoveryRequestGeneration == nil",
        "Self.maximumInterruptedRecoveryAttempts",
        "Self.interruptedRecoveryBackoff",
        "Self.interruptedRecoveryTimeout",
        "CRITICAL: enforcement remained degraded",
        "proxy.setEnforcementEnabled(true)",
    ] {
        try require(
            interruptedRecovery.contains(requiredMarker),
            "interrupted-cleanup recovery lost a safety or retry bound: \(requiredMarker)"
        )
    }

    let interruptedSettlement = try section(
        from: "private func finishInterruptedUnregistrationRecovery(",
        to: "func setMode("
    )
    try require(
        interruptedSettlement.contains("pendingInterruptedRecoveryRequestGeneration == generation")
            && interruptedSettlement.contains("refreshStatus()")
            && !interruptedSettlement.contains("clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution"),
        "mutation acknowledgement clears recovery intent without authenticated runtime proof"
    )

    let unregister = try section(from: "func unregisterDaemon()", to: "func repairHelper()")
    try require(
        unregister.contains("if error != nil")
            && unregister.contains("clearInterruptedUnregistrationRecoveryAfterAuthoritativeResolution()"),
        "successful launchd unregister does not cancel retained recovery or a failed unregister does"
    )

    let modeMutation = try section(from: "func setMode(", to: "func addRule(")
    let enforcementMutation = try section(
        from: "func setEnforcementEnabled(_ enabled: Bool)",
        to: "func installPF()"
    )
    try require(
        modeMutation.contains("invalidatePendingStatusRequest()")
            && modeMutation.contains("refreshStatus()")
            && enforcementMutation.contains("invalidatePendingStatusRequest()")
            && enforcementMutation.contains("refreshStatus()"),
        "mode/enforcement mutation can starve or accept an obsolete status generation"
    )

    let bannerSource = try String(
        contentsOf: repositoryURL.appendingPathComponent("Sources/GUI/Views/HelperBanner.swift"),
        encoding: .utf8
    )
    guard let repairCase = bannerSource.range(of: "case .enabled where needsRepair:"),
          let connectedCase = bannerSource.range(of: "case .enabled where connected:") else {
        throw RegressionFailure(description: "helper repair/connected banner cases are missing")
    }
    try require(
        repairCase.lowerBound < connectedCase.lowerBound,
        "connected state hides a simultaneously degraded helper repair banner"
    )
}

private func testHelperLegacyReconciliationIntegration() throws {
    guard let repositoryPath = ProcessInfo.processInfo.environment["PURESNITCH_REPO_DIR"],
          !repositoryPath.isEmpty else {
        throw RegressionFailure(description: "PURESNITCH_REPO_DIR was not provided")
    }
    let helperServicePath = URL(fileURLWithPath: repositoryPath)
        .appendingPathComponent("Sources/Helper/HelperService.swift")
    let source = try String(contentsOf: helperServicePath, encoding: .utf8)

    func section(from startMarker: String, to endMarker: String) throws -> String {
        guard let start = source.range(of: startMarker) else {
            throw RegressionFailure(description: "HelperService integration marker is missing: \(startMarker)")
        }
        let remainder = source[start.lowerBound...]
        guard let end = remainder.range(of: endMarker) else {
            throw RegressionFailure(description: "HelperService integration marker is missing: \(endMarker)")
        }
        return String(remainder[..<end.lowerBound])
    }

    func compact(_ value: String) -> String {
        value.components(separatedBy: .whitespacesAndNewlines).joined()
    }

    let initializer = try section(from: "init(listener:", to: "func start()")
    let compactInitializer = compact(initializer)
    try require(
        compactInitializer.contains(
            "letpersistedDesired=openedStore.getSetting(HelperSecurityState.desiredSettingKey)"
        ) && compactInitializer.contains("self.enforcementDecisionPersisted=persistedDesired!=nil"),
        "helper does not distinguish a missing desired decision from explicit off"
    )
    try require(
        !compactInitializer.contains("getSetting(HelperSecurityState.legacyPFMigrationPendingSettingKey)")
            && !compactInitializer.contains("getSetting(HelperSecurityState.legacyPFReconciliationSettingKey)"),
        "stale legacy health settings are trusted during helper initialization"
    )

    let startup = try section(from: "func start()", to: "func shutdown()")
    guard let initialHealthWrite = startup.range(of: "recordLegacyPFReconciliation("),
          let legacyProbe = startup.range(of: "legacyStateDetected = try pf.hasLegacyState()") else {
        throw RegressionFailure(description: "helper startup legacy reconciliation markers are missing")
    }
    try require(
        initialHealthWrite.lowerBound < legacyProbe.lowerBound,
        "helper startup probes or mutates PF before invalidating stale reconciliation health"
    )
    try require(
        startup.contains("migrationPending: !hadPersistedDecision")
            && startup.contains("legacyStateDetected = true")
            && startup.contains("legacyStateProbeFailed = true"),
        "missing or unknown legacy state is not kept migration-pending"
    )
    guard let detectedLegacyPending = startup.range(of: "if legacyStateDetected {") ,
          let explicitIntentActivation = startup.range(of: "try activateEnforcementRuntime()") else {
        throw RegressionFailure(description: "detected-legacy pending or activation marker is missing")
    }
    try require(
        detectedLegacyPending.lowerBound < explicitIntentActivation.lowerBound,
        "persisted desired intent can activate before detected legacy state is marked pending"
    )

    guard let preserveStart = startup.range(of: "if legacyStateDetected {") else {
        throw RegressionFailure(description: "legacy ruleset preservation branch is absent")
    }
    let afterPreserveStart = startup[preserveStart.upperBound...]
    guard let preserveEnd = afterPreserveStart.range(of: "} else {") else {
        throw RegressionFailure(description: "missing-desired legacy preservation branch is malformed")
    }
    let preserveBranch = String(afterPreserveStart[..<preserveEnd.lowerBound])
    try require(
        !preserveBranch.contains("try pf.")
            && !preserveBranch.contains("persistDesiredEnforcement"),
        "persisted intent can mutate preserved legacy PF state without a new ruleset choice"
    )

    guard let persistFreshOff = startup.range(of: "try persistDesiredEnforcement(false)"),
          let cleanupFreshOff = startup.range(of: "try pf.cleanupOrphanedState()") else {
        throw RegressionFailure(description: "fresh-install default-off reconciliation is missing")
    }
    try require(
        persistFreshOff.lowerBound < cleanupFreshOff.lowerBound,
        "fresh-install off intent is not durable before checked PF cleanup"
    )
    try require(
        startup.contains("if enforcementDesired")
            && startup.contains("try activateEnforcementRuntime()"),
        "persisted enforcement intent does not drive checked startup reconciliation when no legacy rules exist"
    )

    let healthWriter = try section(
        from: "private func recordLegacyPFReconciliation(",
        to: "private func activateEnforcementRuntime()"
    )
    let compactHealthWriter = compact(healthWriter)
    try require(
        compactHealthWriter.contains("letcheckedSuccess=succeeded&&!migrationPending")
            && compactHealthWriter.contains(
                "HelperSecurityState.legacyPFReconciliationSettingKey,HelperSecurityState.encodeDesired(false)"
            )
            && compactHealthWriter.contains(
                "HelperSecurityState.legacyPFMigrationPendingSettingKey,HelperSecurityState.encodeDesired(migrationPending)"
            )
            && compactHealthWriter.contains("ifcheckedSuccess{")
            && compactHealthWriter.contains(
                "HelperSecurityState.legacyPFReconciliationSettingKey,HelperSecurityState.encodeDesired(true)"
            ),
        "legacy health is not durably written failure-first and success-last"
    )
    try require(
        compactHealthWriter.contains("storedLegacyPFMigrationPending=true")
            && compactHealthWriter.contains("storedLegacyPFReconciliationSucceeded=false")
            && compactHealthWriter.contains("returnfalse"),
        "legacy health persistence failure does not remain pending and unhealthy"
    )

    let stagedActivation = try section(
        from: "private func activateEnforcementWhilePreservingLegacyState()",
        to: "private func stopEnforcementRuntimePreservingDesired()"
    )
    guard let installCurrent = stagedActivation.range(of: "pf.installCurrentStatePreservingLegacy"),
          let startDNS = stagedActivation.range(of: "dns.start("),
          let reconcileLegacy = stagedActivation.range(of: "pf.reconcileLegacyState()") else {
        throw RegressionFailure(description: "pending legacy activation stages are missing")
    }
    try require(
        installCurrent.lowerBound < startDNS.lowerBound && startDNS.lowerBound < reconcileLegacy.lowerBound,
        "pending activation does not stage current PF, start DNS, then reconcile legacy state"
    )
    try require(
        stagedActivation.components(separatedBy: "pf.uninstallCurrentStatePreservingLegacy()").count - 1 == 2,
        "pre-reconciliation activation failures do not preserve legacy PF during rollback"
    )

    let enforcement = try section(
        from: "func setEnforcementEnabled(",
        to: "func prepareForUnregistration("
    )
    let compactEnforcement = compact(enforcement)
    try require(
        compactEnforcement.contains(
            "setEnforcementEnabledAuthorized(enabled,mayResolveLegacyMigration:true,reply:reply)"
        ) && compactEnforcement.contains("guard!migrationWasPending||mayResolveLegacyMigrationelse"),
        "only the authorized enforcement selector cannot resolve pending migration"
    )
    try require(
        source.components(separatedBy: "mayResolveLegacyMigration: true").count - 1 == 1,
        "another helper path can resolve legacy migration without explicit setEnforcementEnabled"
    )
    try require(
        compactEnforcement.contains("guardpf.latestLegacyReconciliationSucceeded==trueelse")
            && compactEnforcement.contains(
                "guardrecordLegacyPFReconciliation(migrationPending:false,succeeded:true)else"
            ),
        "successful enforcement reply does not require checked PF and durable health success"
    )
    try require(
        !source.contains("UserDefaults.standard") && !source.contains("PSLegacy"),
        "per-user legacy markers can trigger privileged helper migration"
    )
}

private func testDatabaseRestore() throws {
    guard let repositoryPath = ProcessInfo.processInfo.environment["PURESNITCH_REPO_DIR"],
          !repositoryPath.isEmpty else {
        throw RegressionFailure(description: "PURESNITCH_REPO_DIR was not provided")
    }
    let helperMain = try String(
        contentsOf: URL(fileURLWithPath: repositoryPath)
            .appendingPathComponent("Sources/Helper/main.swift"),
        encoding: .utf8
    )
    try require(
        !helperMain.contains("SUDO_UID")
            && helperMain.contains("allowedSourceOwnerUIDs: [0]"),
        "root database restore accepts a Homebrew-user-owned source"
    )

    try withTemporaryDirectory { directory in
        let ownerUID = geteuid()
        let targetDirectory = directory.appendingPathComponent("target", isDirectory: true)
        try HelperSecurityState.prepareSupportDirectory(
            at: targetDirectory.path,
            expectedOwnerUID: ownerUID
        )

        let missingResult = try HelperSecurityState.restoreDatabase(
            sourcePath: directory.appendingPathComponent("missing.sqlite").path,
            targetPath: targetDirectory.appendingPathComponent("missing-target.sqlite").path,
            allowedSourceOwnerUIDs: [ownerUID],
            targetOwnerUID: ownerUID
        )
        try require(missingResult == .sourceMissing, "missing restore source did not return sourceMissing")

        try require(
            HelperSecurityState.maximumDatabaseRestoreBytes >= 2 * 1_024 * 1_024 * 1_024,
            "database restore cap regressed below 2 GiB"
        )

        let malformedTarget = targetDirectory.appendingPathComponent("malformed-existing.sqlite")
        let sentinel = Data("do-not-overwrite".utf8)
        try sentinel.write(to: malformedTarget)
        try requireThrows("malformed existing target was trusted") {
            _ = try HelperSecurityState.restoreDatabase(
                sourcePath: directory.appendingPathComponent("still-missing.sqlite").path,
                targetPath: malformedTarget.path,
                allowedSourceOwnerUIDs: [ownerUID],
                targetOwnerUID: ownerUID
            )
        }
        let malformedContents = try Data(contentsOf: malformedTarget)
        try require(malformedContents == sentinel, "malformed existing target was overwritten")

        let source = directory.appendingPathComponent("valid-source.sqlite")
        try createClosedRuleStore(at: source.path) { store in
            try store.setSetting(HelperSecurityState.desiredSettingKey, "1")
        }
        try executeSQLite(
            at: source.path,
            sql: "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;"
        )
        for sidecar in [source.path + "-wal", source.path + "-shm"]
        where FileManager.default.fileExists(atPath: sidecar) {
            try FileManager.default.removeItem(atPath: sidecar)
        }
        let standaloneCopy = directory.appendingPathComponent("standalone-copy.sqlite")
        try FileManager.default.copyItem(at: source, to: standaloneCopy)
        try withContext("validate standalone fixture copy") {
            try executeSQLite(at: standaloneCopy.path, sql: "PRAGMA integrity_check;")
        }

        let existingTarget = targetDirectory.appendingPathComponent("existing.sqlite")
        try createClosedRuleStore(at: existingTarget.path)
        try HelperSecurityState.hardenDatabaseFiles(existingTarget.path, expectedOwnerUID: ownerUID)
        let existingResult = try withContext("validate existing restore target") {
            try HelperSecurityState.restoreDatabase(
                sourcePath: source.path,
                targetPath: existingTarget.path,
                allowedSourceOwnerUIDs: [ownerUID],
                targetOwnerUID: ownerUID
            )
        }
        try require(existingResult == .targetAlreadyExists, "validated existing target was not preserved")

        let linkedTarget = targetDirectory.appendingPathComponent("linked-target.sqlite")
        try FileManager.default.createSymbolicLink(at: linkedTarget, withDestinationURL: existingTarget)
        try requireThrows("symlink existing target was trusted") {
            _ = try HelperSecurityState.restoreDatabase(
                sourcePath: source.path,
                targetPath: linkedTarget.path,
                allowedSourceOwnerUIDs: [ownerUID],
                targetOwnerUID: ownerUID
            )
        }

        let sourceSize = try fileSize(at: source.path)
        let boundaryTarget = targetDirectory.appendingPathComponent("boundary.sqlite")
        let boundaryResult = try withContext("restore at injected byte boundary") {
            try HelperSecurityState.restoreDatabase(
                sourcePath: source.path,
                targetPath: boundaryTarget.path,
                allowedSourceOwnerUIDs: [ownerUID],
                targetOwnerUID: ownerUID,
                maximumBytes: sourceSize
            )
        }
        try require(boundaryResult == .restored, "valid database at the injected byte limit was rejected")
        let restoredPermissions = try filePermissions(at: boundaryTarget.path)
        let restoredOwner = try fileOwnerUID(at: boundaryTarget.path)
        try require(FileManager.default.fileExists(atPath: source.path), "successful restore removed its source backup")
        try require(restoredPermissions == 0o600, "restored database was not mode 0600")
        try require(restoredOwner == ownerUID, "restored database owner changed")
        try require(
            !FileManager.default.fileExists(atPath: boundaryTarget.path + "-wal")
                && !FileManager.default.fileExists(atPath: boundaryTarget.path + "-shm"),
            "restore created SQLite sidecars beside the target"
        )
        do {
            let restoredStore = try RuleStore(path: boundaryTarget.path)
            try require(
                restoredStore.getSetting(HelperSecurityState.desiredSettingKey) == "1",
                "restored database lost persisted settings"
            )
        }

        let cellarVersion = directory
            .appendingPathComponent("Cellar", isDirectory: true)
            .appendingPathComponent("puresnitch-migrate-v021", isDirectory: true)
            .appendingPathComponent("0.2.0", isDirectory: true)
        let migrationDirectory = cellarVersion.appendingPathComponent("migration", isDirectory: true)
        try FileManager.default.createDirectory(
            at: migrationDirectory,
            withIntermediateDirectories: true
        )
        let cellarSource = migrationDirectory.appendingPathComponent("puresnitch.sqlite")
        try createClosedRuleStore(at: cellarSource.path) { store in
            try store.setSetting(HelperSecurityState.desiredSettingKey, "1")
        }
        try executeSQLite(
            at: cellarSource.path,
            sql: "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;"
        )
        for sidecar in [cellarSource.path + "-wal", cellarSource.path + "-shm"]
        where FileManager.default.fileExists(atPath: sidecar) {
            try FileManager.default.removeItem(atPath: sidecar)
        }
        try HelperSecurityState.hardenDatabaseFiles(cellarSource.path, expectedOwnerUID: ownerUID)
        let cellarSourcePermissions = try filePermissions(at: cellarSource.path)
        try require(
            cellarSourcePermissions == 0o600,
            "Homebrew Cellar backup fixture was not mode 0600"
        )

        let optDirectory = directory.appendingPathComponent("opt", isDirectory: true)
        try FileManager.default.createDirectory(at: optDirectory, withIntermediateDirectories: true)
        let optLink = optDirectory.appendingPathComponent("puresnitch-migrate-v021")
        try FileManager.default.createSymbolicLink(at: optLink, withDestinationURL: cellarVersion)
        let optSource = optLink
            .appendingPathComponent("migration", isDirectory: true)
            .appendingPathComponent("puresnitch.sqlite")
        let optTarget = targetDirectory.appendingPathComponent("from-homebrew-opt.sqlite")
        let optResult = try HelperSecurityState.restoreDatabase(
            sourcePath: optSource.path,
            targetPath: optTarget.path,
            allowedSourceOwnerUIDs: [ownerUID],
            targetOwnerUID: ownerUID
        )
        try require(
            optResult == .restored && FileManager.default.fileExists(atPath: optTarget.path),
            "regular backup behind a Homebrew opt intermediate symlink was rejected"
        )

        try Data("stale-wal".utf8).write(to: URL(fileURLWithPath: source.path + "-wal"))
        try Data("stale-shm".utf8).write(to: URL(fileURLWithPath: source.path + "-shm"))

        let sidecarTarget = targetDirectory.appendingPathComponent("sidecar-target.sqlite")
        try requireThrows("source with unvalidated SQLite sidecars was restored") {
            _ = try HelperSecurityState.restoreDatabase(
                sourcePath: source.path,
                targetPath: sidecarTarget.path,
                allowedSourceOwnerUIDs: [ownerUID],
                targetOwnerUID: ownerUID
            )
        }
        try require(
            !FileManager.default.fileExists(atPath: sidecarTarget.path),
            "rejected sidecar-bearing source created a target"
        )

        let wrongOwner = ownerUID == uid_t.max ? ownerUID - 1 : ownerUID + 1
        let wrongOwnerTarget = targetDirectory.appendingPathComponent("wrong-owner.sqlite")
        try requireThrows("source owner outside the allowlist was restored") {
            _ = try HelperSecurityState.restoreDatabase(
                sourcePath: source.path,
                targetPath: wrongOwnerTarget.path,
                allowedSourceOwnerUIDs: [wrongOwner],
                targetOwnerUID: ownerUID
            )
        }
        try require(!FileManager.default.fileExists(atPath: wrongOwnerTarget.path), "wrong-owner restore created a target")

        let sourceLink = directory.appendingPathComponent("source-link.sqlite")
        try FileManager.default.createSymbolicLink(at: sourceLink, withDestinationURL: source)
        let symlinkTarget = targetDirectory.appendingPathComponent("from-symlink.sqlite")
        try requireThrows("symlink restore source was followed") {
            _ = try HelperSecurityState.restoreDatabase(
                sourcePath: sourceLink.path,
                targetPath: symlinkTarget.path,
                allowedSourceOwnerUIDs: [ownerUID],
                targetOwnerUID: ownerUID
            )
        }
        try require(!FileManager.default.fileExists(atPath: symlinkTarget.path), "symlink restore created a target")

        let oversizedTarget = targetDirectory.appendingPathComponent("oversized.sqlite")
        try requireThrows("restore ignored its maximum byte limit") {
            _ = try HelperSecurityState.restoreDatabase(
                sourcePath: source.path,
                targetPath: oversizedTarget.path,
                allowedSourceOwnerUIDs: [ownerUID],
                targetOwnerUID: ownerUID,
                maximumBytes: 1
            )
        }

        let sparseSource = directory.appendingPathComponent("oversized-sparse.sqlite")
        try Data([0]).write(to: sparseSource)
        let sparseSize = HelperSecurityState.maximumDatabaseRestoreBytes + 1
        guard truncate(sparseSource.path, off_t(sparseSize)) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        try requireThrows("sparse backup larger than the production cap was restored") {
            _ = try HelperSecurityState.restoreDatabase(
                sourcePath: sparseSource.path,
                targetPath: targetDirectory.appendingPathComponent("sparse-target.sqlite").path,
                allowedSourceOwnerUIDs: [ownerUID],
                targetOwnerUID: ownerUID
            )
        }

        let emptySource = directory.appendingPathComponent("empty.sqlite")
        try Data().write(to: emptySource)
        try requireThrows("empty database backup was restored") {
            _ = try HelperSecurityState.restoreDatabase(
                sourcePath: emptySource.path,
                targetPath: targetDirectory.appendingPathComponent("empty-target.sqlite").path,
                allowedSourceOwnerUIDs: [ownerUID],
                targetOwnerUID: ownerUID
            )
        }

        let corruptSource = directory.appendingPathComponent("corrupt.sqlite")
        try Data("not-a-sqlite-database".utf8).write(to: corruptSource)
        try requireThrows("corrupt database backup was restored") {
            _ = try HelperSecurityState.restoreDatabase(
                sourcePath: corruptSource.path,
                targetPath: targetDirectory.appendingPathComponent("corrupt-target.sqlite").path,
                allowedSourceOwnerUIDs: [ownerUID],
                targetOwnerUID: ownerUID
            )
        }

        let missingSchema = directory.appendingPathComponent("missing-schema.sqlite")
        try createClosedRuleStore(at: missingSchema.path)
        try executeSQLite(at: missingSchema.path, sql: "DROP TABLE connections;")
        try requireThrows("database missing a required table was restored") {
            _ = try HelperSecurityState.restoreDatabase(
                sourcePath: missingSchema.path,
                targetPath: targetDirectory.appendingPathComponent("missing-schema-target.sqlite").path,
                allowedSourceOwnerUIDs: [ownerUID],
                targetOwnerUID: ownerUID
            )
        }

        let unexpectedSchema = directory.appendingPathComponent("unexpected-schema.sqlite")
        try createClosedRuleStore(at: unexpectedSchema.path)
        try executeSQLite(at: unexpectedSchema.path, sql: "CREATE TABLE injected_payload(value TEXT);")
        try requireThrows("database with an unexpected schema object was restored") {
            _ = try HelperSecurityState.restoreDatabase(
                sourcePath: unexpectedSchema.path,
                targetPath: targetDirectory.appendingPathComponent("schema-target.sqlite").path,
                allowedSourceOwnerUIDs: [ownerUID],
                targetOwnerUID: ownerUID
            )
        }
    }
}

private func filePermissions(at path: String) throws -> mode_t {
    var info = stat()
    guard lstat(path, &info) == 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    return info.st_mode & 0o777
}

private func fileOwnerUID(at path: String) throws -> uid_t {
    var info = stat()
    guard lstat(path, &info) == 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    return info.st_uid
}

private func fileSize(at path: String) throws -> Int64 {
    var info = stat()
    guard lstat(path, &info) == 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    return Int64(info.st_size)
}

private func fileFlags(at path: String) throws -> UInt32 {
    var info = stat()
    guard lstat(path, &info) == 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    return UInt32(info.st_flags)
}

private func executeSQLite(at path: String, sql: String) throws {
    var database: OpaquePointer?
    guard sqlite3_open(path, &database) == SQLITE_OK, let database else {
        if database != nil { sqlite3_close(database) }
        throw RegressionFailure(description: "could not open SQLite fixture")
    }
    defer { sqlite3_close(database) }
    var errorMessage: UnsafeMutablePointer<CChar>?
    let result = sqlite3_exec(database, sql, nil, nil, &errorMessage)
    guard result == SQLITE_OK else {
        let message = errorMessage.map { String(cString: $0) } ?? "unknown SQLite fixture error"
        sqlite3_free(errorMessage)
        throw RegressionFailure(description: message)
    }
}

private func createClosedRuleStore(
    at path: String,
    configure: (RuleStore) throws -> Void = { _ in }
) throws {
    var store: RuleStore? = try RuleStore(path: path)
    try configure(store!)
    store = nil
}

private func testPendingDNSAsks() throws {
    let independent = PendingDNSAsks(capacity: 2)
    let firstCount = LockedCounter()
    let secondCount = LockedCounter()
    let first = try requireID(independent.register { _ in firstCount.increment() })
    let second = try requireID(independent.register { _ in secondCount.increment() })
    try require(first != second, "same-domain-equivalent asks reused one identifier")
    try require(independent.count == 2, "independent asks were not both retained")
    try require(independent.register { _ in } == nil, "capacity overflow was retained")
    try require(independent.settle(id: first, allow: true), "first ask did not settle")
    try require(!independent.settle(id: first, allow: false), "first ask settled twice")
    try require(firstCount.value == 1 && secondCount.value == 0, "asks did not settle independently")
    try require(independent.settle(id: second, allow: false), "second ask did not settle")
    try require(secondCount.value == 1 && independent.count == 0, "second ask settlement was incorrect")

    let drained = PendingDNSAsks(capacity: 4)
    let drainCount = LockedCounter()
    for _ in 0..<4 {
        try require(drained.register { _ in drainCount.increment() } != nil, "drain fixture registration failed")
    }
    try require(drained.drain(allow: true) == 4, "drain did not report every callback")
    try require(drained.count == 0 && drainCount.value == 4, "drain left pending callbacks")
    try require(drained.drain(allow: false) == 0, "empty drain should be a no-op")

    let configuredCap = PendingDNSAsks(capacity: 256)
    for index in 0..<256 {
        try require(configuredCap.register { _ in } != nil, "configured cap rejected entry \(index)")
    }
    try require(configuredCap.register { _ in } == nil, "configured 256-entry cap accepted entry 257")
    try require(configuredCap.drain(allow: true) == 256, "configured-cap drain count was incorrect")

    for iteration in 0..<500 {
        let racing = PendingDNSAsks(capacity: 1)
        let callbackCount = LockedCounter()
        let id = try requireID(racing.register { _ in callbackCount.increment() })
        DispatchQueue.concurrentPerform(iterations: 2) { contender in
            _ = racing.settle(id: id, allow: contender == 0)
        }
        try require(
            callbackCount.value == 1 && racing.count == 0,
            "reply/timeout race violated exactly-once behavior at iteration \(iteration)"
        )
    }
}

private func requireID(_ id: UUID?) throws -> UUID {
    guard let id else { throw RegressionFailure(description: "pending ask registration unexpectedly failed") }
    return id
}

private func testStandalonePFCleanupGate() throws {
    let serviceLabel = "io.moamenbasel.puresnitch.helper"
    var checkedTarget: String?
    try HelperDaemonCleanupGate.requireStopped(serviceLabel: serviceLabel) { target in
        checkedTarget = target
        return .exited(113)
    }
    try require(
        checkedTarget == "system/\(serviceLabel)",
        "daemon cleanup gate checked the wrong launchd domain or service"
    )

    var liveRejected = false
    do {
        try HelperDaemonCleanupGate.requireStopped(serviceLabel: serviceLabel) { _ in .exited(0) }
    } catch HelperDaemonCleanupGateError.daemonIsRunning {
        liveRejected = true
    } catch {
        throw RegressionFailure(description: "live daemon produced the wrong cleanup-gate error: \(error)")
    }
    try require(liveRejected, "live launchd daemon was treated as absent")

    func requireUnknown(
        result: HelperDaemonCleanupGate.CommandResult,
        expectedStatus: Int32?
    ) throws {
        do {
            try HelperDaemonCleanupGate.requireStopped(serviceLabel: serviceLabel) { _ in result }
            throw RegressionFailure(description: "unknown launchd result permitted standalone PF cleanup")
        } catch HelperDaemonCleanupGateError.daemonStateUnknown(let status) {
            try require(status == expectedStatus, "cleanup gate lost the unknown launchd status")
        } catch is RegressionFailure {
            throw RegressionFailure(description: "unknown launchd result permitted standalone PF cleanup")
        } catch {
            throw RegressionFailure(description: "unknown launchd result produced the wrong error: \(error)")
        }
    }
    try requireUnknown(result: .exited(1), expectedStatus: 1)
    try requireUnknown(result: .signaled(9), expectedStatus: nil)

    try withTemporaryDirectory { directory in
        let pfConfURL = directory.appendingPathComponent("pf.conf")
        try "set skip on lo0\n".write(to: pfConfURL, atomically: true, encoding: .utf8)

        for result in [
            HelperDaemonCleanupGate.CommandResult.exited(0),
            .exited(1),
            .signaled(9),
        ] {
            let runner = FakePFRunner()
            let manager = PFManager(
                commandRunner: runner.run,
                anchorPath: directory.appendingPathComponent("blocked-anchor-\(UUID().uuidString)").path,
                enableTokenPath: directory.appendingPathComponent("blocked-token-\(UUID().uuidString)").path,
                processLockPath: directory.appendingPathComponent("blocked-lock-\(UUID().uuidString)").path,
                legacyAnchorPath: directory.appendingPathComponent("blocked-legacy-\(UUID().uuidString)").path,
                legacyPFConfPath: pfConfURL.path,
                daemonAbsenceChecker: {
                    try HelperDaemonCleanupGate.requireStopped(serviceLabel: serviceLabel) { _ in result }
                }
            )
            try requireThrows("standalone cleanup ignored a non-absent daemon result") {
                try manager.cleanupOrphanedStateForStandaloneProcess()
            }
            try require(
                runner.invocations.isEmpty,
                "standalone cleanup invoked pfctl before proving daemon absence"
            )
        }

        var sequence: [String] = []
        let manager = PFManager(
            commandRunner: { _, arguments in
                sequence.append("pf:\(arguments.joined(separator: " "))")
                return ""
            },
            anchorPath: directory.appendingPathComponent("allowed-anchor").path,
            enableTokenPath: directory.appendingPathComponent("allowed-token").path,
            processLockPath: directory.appendingPathComponent("allowed-lock").path,
            legacyAnchorPath: directory.appendingPathComponent("allowed-legacy").path,
            legacyPFConfPath: pfConfURL.path,
            daemonAbsenceChecker: {
                sequence.append("gate")
                try HelperDaemonCleanupGate.requireStopped(serviceLabel: serviceLabel) { _ in .exited(113) }
            }
        )
        try manager.cleanupOrphanedStateForStandaloneProcess()
        try require(sequence.first == "gate", "standalone cleanup did not check daemon absence first")
        try require(
            sequence.dropFirst().contains { $0.hasPrefix("pf:") },
            "daemon-absent standalone cleanup never reached the fake PF runner"
        )
    }
}

private func testPFLegacyReconciliationHealth() throws {
    try withTemporaryDirectory { directory in
        let pfConfURL = directory.appendingPathComponent("pf.conf")
        let legacyAnchorURL = directory.appendingPathComponent("legacy-anchor")
        try "set skip on lo0\n".write(to: pfConfURL, atomically: true, encoding: .utf8)

        let runner = FakePFRunner()
        let manager = PFManager(
            commandRunner: runner.run,
            anchorPath: directory.appendingPathComponent("anchor").path,
            enableTokenPath: directory.appendingPathComponent("token").path,
            processLockPath: directory.appendingPathComponent("pf.lock").path,
            legacyAnchorPath: legacyAnchorURL.path,
            legacyPFConfPath: pfConfURL.path
        )
        try require(
            manager.latestLegacyReconciliationSucceeded == nil,
            "PF manager reported legacy reconciliation before a checked cleanup"
        )
        let initiallyHasLegacyState = try manager.hasLegacyState()
        try require(!initiallyHasLegacyState, "empty legacy PF fixture was detected as pending migration")
        try require(
            runner.invocations.contains { $0.arguments == ["-a", "puresnitch", "-sr"] },
            "legacy-state probe did not inspect runtime anchor rules"
        )

        let legacyPFConf = """
        set skip on lo0
        anchor "puresnitch"
        load anchor "puresnitch" from "/etc/pf.anchors/puresnitch"

        """
        try legacyPFConf.write(to: pfConfURL, atomically: true, encoding: .utf8)
        let pfConfLegacyState = try manager.hasLegacyState()
        try require(pfConfLegacyState, "legacy pf.conf declarations were not detected")

        try "# legacy anchor\nblock out all\n".write(
            to: legacyAnchorURL,
            atomically: true,
            encoding: .utf8
        )
        let anchorLegacyState = try manager.hasLegacyState()
        try require(anchorLegacyState, "non-empty legacy anchor was not detected")

        try manager.cleanupOrphanedState()
        try require(
            manager.latestLegacyReconciliationSucceeded == true,
            "successful checked legacy cleanup did not publish healthy reconciliation"
        )
        try require(
            !FileManager.default.fileExists(atPath: legacyAnchorURL.path),
            "successful checked legacy cleanup retained the canonical cleared anchor"
        )
        let legacyStateAfterCleanup = try manager.hasLegacyState()
        try require(!legacyStateAfterCleanup, "successful checked cleanup left legacy PF state detectable")

        let clearedLegacyAnchor = "# PureSnitch legacy anchor cleared during migration.\n"
        for (operation, failingArguments) in [
            ("flush", ["-a", "puresnitch", "-F", "rules"]),
            ("unload", ["-a", "puresnitch", "-f", "/dev/null"]),
        ] {
            try "# legacy anchor\nblock out all\n".write(
                to: legacyAnchorURL,
                atomically: true,
                encoding: .utf8
            )
            runner.failingArguments = failingArguments
            try requireThrows("legacy PF \(operation) failure was not reported") {
                try manager.cleanupOrphanedState()
            }
            try require(
                manager.latestLegacyReconciliationSucceeded == false,
                "failed checked legacy \(operation) published healthy reconciliation"
            )
            let retainedAnchor = try String(contentsOf: legacyAnchorURL, encoding: .utf8)
            try require(
                retainedAnchor == clearedLegacyAnchor,
                "legacy \(operation) failure did not retain the exact canonical cleared anchor"
            )

            runner.failingArguments = nil
            try manager.cleanupOrphanedState()
            try require(
                manager.latestLegacyReconciliationSucceeded == true,
                "successful retry did not replace stale legacy \(operation) failure"
            )
            try require(
                !FileManager.default.fileExists(atPath: legacyAnchorURL.path),
                "successful retry retained the canonical cleared legacy anchor after \(operation) failure"
            )
        }
    }

    try withTemporaryDirectory { directory in
        let anchorURL = directory.appendingPathComponent("current-anchor")
        let tokenURL = directory.appendingPathComponent("current-token")
        let legacyAnchorURL = directory.appendingPathComponent("legacy-anchor")
        let pfConfURL = directory.appendingPathComponent("pf.conf")
        let legacyPFConf = """
        set skip on lo0
        anchor "puresnitch"
        load anchor "puresnitch" from "/etc/pf.anchors/puresnitch"

        """
        let legacyAnchor = "# legacy anchor\nblock out all\n"
        try legacyPFConf.write(to: pfConfURL, atomically: true, encoding: .utf8)
        try legacyAnchor.write(to: legacyAnchorURL, atomically: true, encoding: .utf8)

        let runner = FakePFRunner()
        let manager = PFManager(
            commandRunner: runner.run,
            anchorPath: anchorURL.path,
            enableTokenPath: tokenURL.path,
            processLockPath: directory.appendingPathComponent("pf.lock").path,
            legacyAnchorPath: legacyAnchorURL.path,
            legacyPFConfPath: pfConfURL.path
        )
        let beforeInstall = runner.invocations.count
        try manager.installCurrentStatePreservingLegacy(rules: [])
        let installCalls = Array(runner.invocations.dropFirst(beforeInstall))
        try require(manager.isLoaded, "staged current PF state was not marked active")
        try require(
            manager.latestLegacyReconciliationSucceeded == nil,
            "staging current PF falsely reported legacy reconciliation"
        )
        try require(
            !installCalls.contains { call in
                call.arguments.count >= 2
                    && call.arguments[0] == "-a"
                    && call.arguments[1] == "puresnitch"
            },
            "staging current PF invoked a legacy anchor command"
        )
        let stagedPFConf = try String(contentsOf: pfConfURL, encoding: .utf8)
        let stagedLegacyAnchor = try String(contentsOf: legacyAnchorURL, encoding: .utf8)
        try require(
            stagedPFConf == legacyPFConf && stagedLegacyAnchor == legacyAnchor,
            "staging current PF mutated legacy files"
        )

        runner.failingArguments = ["-a", "puresnitch", "-F", "rules"]
        try requireThrows("failed legacy reconciliation was accepted") {
            try manager.reconcileLegacyState()
        }
        try require(
            manager.isLoaded && FileManager.default.fileExists(atPath: tokenURL.path),
            "failed legacy reconciliation removed staged current protection"
        )
        try require(
            manager.latestLegacyReconciliationSucceeded == false,
            "failed staged reconciliation published success"
        )

        runner.failingArguments = nil
        try manager.reconcileLegacyState()
        try require(
            manager.isLoaded && manager.latestLegacyReconciliationSucceeded == true,
            "successful legacy reconciliation did not retain current protection and publish success"
        )
        let legacyRemaining = try manager.hasLegacyState()
        try require(!legacyRemaining, "successful staged reconciliation left legacy PF state")
        try manager.uninstallCurrentStatePreservingLegacy()
    }

    try withTemporaryDirectory { directory in
        let tokenURL = directory.appendingPathComponent("current-token")
        let legacyAnchorURL = directory.appendingPathComponent("legacy-anchor")
        let pfConfURL = directory.appendingPathComponent("pf.conf")
        let legacyPFConf = """
        set skip on lo0
        anchor "puresnitch"
        load anchor "puresnitch" from "/etc/pf.anchors/puresnitch"

        """
        let legacyAnchor = "# legacy anchor\nblock out all\n"
        try legacyPFConf.write(to: pfConfURL, atomically: true, encoding: .utf8)
        try legacyAnchor.write(to: legacyAnchorURL, atomically: true, encoding: .utf8)

        let runner = FakePFRunner()
        let manager = PFManager(
            commandRunner: runner.run,
            anchorPath: directory.appendingPathComponent("current-anchor").path,
            enableTokenPath: tokenURL.path,
            processLockPath: directory.appendingPathComponent("pf.lock").path,
            legacyAnchorPath: legacyAnchorURL.path,
            legacyPFConfPath: pfConfURL.path
        )
        try manager.installCurrentStatePreservingLegacy(rules: [])
        let beforeUninstall = runner.invocations.count
        try manager.uninstallCurrentStatePreservingLegacy()
        let uninstallCalls = Array(runner.invocations.dropFirst(beforeUninstall))
        try require(!manager.isLoaded, "current-only rollback retained loaded state")
        try require(!FileManager.default.fileExists(atPath: tokenURL.path), "current-only rollback retained PF token")
        try require(
            !uninstallCalls.contains { call in
                call.arguments.count >= 2
                    && call.arguments[0] == "-a"
                    && call.arguments[1] == "puresnitch"
            },
            "current-only rollback invoked a legacy anchor command"
        )
        let preservedPFConf = try String(contentsOf: pfConfURL, encoding: .utf8)
        let preservedLegacyAnchor = try String(contentsOf: legacyAnchorURL, encoding: .utf8)
        try require(
            preservedPFConf == legacyPFConf && preservedLegacyAnchor == legacyAnchor,
            "current-only rollback mutated legacy PF files"
        )
    }
}

private func testPFManagerLifecycleAndRendering() throws {
    try withTemporaryDirectory { directory in
        let anchorURL = directory.appendingPathComponent("pf-anchor.conf")
        let tokenURL = directory.appendingPathComponent("pf-token")
        let lockURL = directory.appendingPathComponent("pf.lock")
        let legacyAnchorURL = directory.appendingPathComponent("legacy-anchor")
        let pfConfURL = directory.appendingPathComponent("pf.conf")
        try "set skip on lo0\n".write(to: pfConfURL, atomically: true, encoding: .utf8)

        let runner = FakePFRunner()
        let manager = PFManager(
            commandRunner: runner.run,
            anchorPath: anchorURL.path,
            enableTokenPath: tokenURL.path,
            processLockPath: lockURL.path,
            legacyAnchorPath: legacyAnchorURL.path,
            legacyPFConfPath: pfConfURL.path
        )
        try manager.install()
        try require(manager.isLoaded, "successful install did not mark PF loaded")
        try require(FileManager.default.fileExists(atPath: tokenURL.path), "install did not persist the PF token")
        try require(
            runner.invocations.contains { $0.arguments == ["-sr"] },
            "install did not preflight the active com.apple/* parent anchor"
        )

        let future = Date().addingTimeInterval(600)
        let past = Date().addingTimeInterval(-600)
        let rules = [
            Rule(remoteIP: "203.0.113.9/32", action: .deny, scope: .ip, expiresAt: future),
            Rule(remoteIP: "203.0.113.10", direction: .incoming, action: .deny, scope: .ip, expiresAt: future),
            Rule(remoteIP: "203.0.113.11", direction: .any, action: .deny, scope: .ip, expiresAt: future),
            Rule(remoteIP: "198.51.100.1", action: .allow, scope: .ip),
            Rule(processBundleId: "com.example.app", remoteIP: "198.51.100.2", action: .deny, scope: .process),
            Rule(remoteIP: "198.51.100.3", action: .deny, scope: .ip, profile: "work"),
            Rule(remoteIP: "198.51.100.4", action: .deny, scope: .ip, expiresAt: past),
            Rule(remoteIP: "198.51.100.5", action: .deny, scope: .ip, enabled: false),
            Rule(remoteHost: "blocked.example", action: .deny, scope: .domain),
            Rule(remoteIP: "203.0.113.12\npass all", action: .deny, scope: .ip),
            Rule(remoteHost: "203.0.113.13 }\nset skip on lo0", action: .deny, scope: .domain),
            Rule(action: .deny, scope: .any),
        ]
        try manager.applyRules(rules)

        let anchor = try String(contentsOf: anchorURL, encoding: .utf8)
        let activeLines = anchor.split(whereSeparator: \Character.isNewline).filter { !$0.hasPrefix("#") }
        let expectedLines: Set<Substring> = [
            "block out quick proto { tcp udp } to 203.0.113.9/32",
            "block in quick proto { tcp udp } from 203.0.113.10",
            "block out quick proto { tcp udp } to 203.0.113.11",
            "block in quick proto { tcp udp } from 203.0.113.11",
        ]
        try require(
            Set(activeLines) == expectedLines,
            "PF anchor did not render only eligible default host-wide denies with safe directions: \(anchor)"
        )
        try require(!anchor.contains("pass "), "PF anchor emitted a pass rule")
        try require(!anchor.contains("set "), "PF anchor emitted a global set directive")
        try require(!anchor.contains("blocked.example"), "domain name leaked into PF anchor")
        try require(!anchor.contains("203.0.113.12\n"), "newline injection leaked into PF anchor")

        let currentFlush = ["-a", PFManager.anchorName, "-F", "rules"]
        runner.failingArguments = currentFlush
        try requireThrows("uninstall should report a flush failure") { try manager.uninstall() }
        try require(manager.isLoaded, "failed cleanup incorrectly marked PF unloaded")
        try require(FileManager.default.fileExists(atPath: tokenURL.path), "failed cleanup released its PF token")
        try require(
            runner.invocations.contains { $0.arguments == ["-a", PFManager.anchorName, "-f", "/dev/null"] },
            "cleanup stopped before attempting runtime-anchor unload"
        )

        runner.failingArguments = nil
        try manager.uninstall()
        try require(!manager.isLoaded, "successful cleanup retained loaded state")
        try require(!FileManager.default.fileExists(atPath: tokenURL.path), "successful cleanup retained token file")
        try require(
            runner.invocations.contains { $0.arguments == ["-s", "References"] }
                && runner.invocations.contains { $0.arguments == ["-X", "424242"] },
            "successful cleanup did not verify and release its active PF reference"
        )
        let cleanupCalls = runner.invocations.filter { $0.arguments.contains("-F") }
        try require(!cleanupCalls.isEmpty, "cleanup did not flush runtime rules")
        try require(
            cleanupCalls.allSatisfy { invocation in
                guard let flag = invocation.arguments.firstIndex(of: "-F") else { return false }
                return invocation.arguments.indices.contains(flag + 1) && invocation.arguments[flag + 1] == "rules"
            },
            "cleanup used a PF-wide flush instead of -F rules"
        )
    }

    try withTemporaryDirectory { directory in
        let pfConfURL = directory.appendingPathComponent("pf.conf")
        try "set skip on lo0\n".write(to: pfConfURL, atomically: true, encoding: .utf8)
        let runner = FakePFRunner()
        runner.parentAnchorActive = false
        let manager = PFManager(
            commandRunner: runner.run,
            anchorPath: directory.appendingPathComponent("anchor").path,
            enableTokenPath: directory.appendingPathComponent("token").path,
            processLockPath: directory.appendingPathComponent("pf.lock").path,
            legacyAnchorPath: directory.appendingPathComponent("legacy-anchor").path,
            legacyPFConfPath: pfConfURL.path
        )
        try requireThrows("install should fail without active com.apple/* parent anchor") { try manager.install() }
        try require(!manager.isLoaded, "failed parent-anchor preflight marked PF loaded")
        try require(!runner.invocations.contains { $0.arguments == ["-E"] }, "preflight failure enabled PF")
    }

    try withTemporaryDirectory { directory in
        let pfConfURL = directory.appendingPathComponent("pf.conf")
        let tokenURL = directory.appendingPathComponent("token")
        try "set skip on lo0\n".write(to: pfConfURL, atomically: true, encoding: .utf8)
        try "424242\n".write(to: tokenURL, atomically: true, encoding: .utf8)
        let runner = FakePFRunner()
        runner.referencesContainToken = false
        let manager = PFManager(
            commandRunner: runner.run,
            anchorPath: directory.appendingPathComponent("anchor").path,
            enableTokenPath: tokenURL.path,
            processLockPath: directory.appendingPathComponent("pf.lock").path,
            legacyAnchorPath: directory.appendingPathComponent("legacy-anchor").path,
            legacyPFConfPath: pfConfURL.path
        )
        try require(manager.isLoaded, "persisted token did not produce conservative loaded state")
        try manager.cleanupOrphanedState()
        try require(!manager.isLoaded, "stale-token cleanup retained loaded state")
        try require(!FileManager.default.fileExists(atPath: tokenURL.path), "stale token was not unlinked")
        try require(
            runner.invocations.contains { $0.arguments == ["-s", "References"] },
            "stale token was not checked against active PF references"
        )
        try require(
            !runner.invocations.contains { $0.arguments == ["-X", "424242"] },
            "stale token cleanup released a reference that was already absent"
        )
    }

    try withTemporaryDirectory { directory in
        let pfConfURL = directory.appendingPathComponent("pf.conf")
        let original = """
        set skip on lo0
        anchor "puresnitch"
        load anchor "puresnitch" from "/etc/pf.anchors/puresnitch"

        """
        try original.write(to: pfConfURL, atomically: true, encoding: .utf8)
        guard chmod(pfConfURL.path, mode_t(0o640)) == 0,
              chflags(pfConfURL.path, UInt32(UF_NODUMP)) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        let originalOwner = try fileOwnerUID(at: pfConfURL.path)
        let runner = FakePFRunner()
        let manager = PFManager(
            commandRunner: runner.run,
            anchorPath: directory.appendingPathComponent("anchor").path,
            enableTokenPath: directory.appendingPathComponent("token").path,
            processLockPath: directory.appendingPathComponent("pf.lock").path,
            legacyAnchorPath: directory.appendingPathComponent("legacy-anchor").path,
            legacyPFConfPath: pfConfURL.path
        )
        try manager.install()
        let migrated = try String(contentsOf: pfConfURL, encoding: .utf8)
        let migratedFlags = try fileFlags(at: pfConfURL.path)
        let migratedPermissions = try filePermissions(at: pfConfURL.path)
        let migratedOwner = try fileOwnerUID(at: pfConfURL.path)
        try require(migrated == "set skip on lo0\n", "legacy PF declarations were not removed exactly")
        try require((migratedFlags & UInt32(UF_NODUMP)) != 0, "PF migration dropped UF_NODUMP")
        try require(migratedPermissions == 0o640, "PF migration changed pf.conf mode")
        try require(migratedOwner == originalOwner, "PF migration changed pf.conf owner")
        try manager.uninstall()
    }
}

private func testDNSProxyIsolationAndCleanup() throws {
    let port = try findAvailablePort()
    let proxy = DNSProxy()
    proxy.mode = .silentDeny
    // Force the ask path while leaving no onAsk client. silentDeny must still
    // complete immediately with NXDOMAIN instead of suspending the query.
    proxy.rules = [Rule(remoteHost: "regression.invalid", action: .ask, scope: .domain)]
    try withContext("start primary DNS proxy") { try proxy.start(port: port) }
    defer { proxy.stop() }

    try require(proxy.running && proxy.port == port, "DNS proxy did not report its active high port")
    let tcpSockets = processOutput(
        executable: "/usr/sbin/lsof",
        arguments: ["-nP", "-a", "-p", "\(getpid())", "-iTCP:\(port)", "-sTCP:LISTEN"]
    ).output
    let udpSockets = processOutput(
        executable: "/usr/sbin/lsof",
        arguments: ["-nP", "-a", "-p", "\(getpid())", "-iUDP:\(port)"]
    ).output
    try require(tcpSockets.contains("127.0.0.1:\(port)"), "TCP listener was not bound to IPv4 loopback: \(tcpSockets)")
    try require(udpSockets.contains("127.0.0.1:\(port)"), "UDP listener was not bound to IPv4 loopback: \(udpSockets)")
    try require(!tcpSockets.contains("*:\(port)"), "TCP listener was wildcard-bound: \(tcpSockets)")
    try require(!udpSockets.contains("*:\(port)"), "UDP listener was wildcard-bound: \(udpSockets)")
    try require(tcpConnects(host: "127.0.0.1", port: port), "loopback TCP listener refused a connection")

    if let lanAddress = firstNonLoopbackIPv4() {
        try require(!tcpConnects(host: lanAddress, port: port), "DNS listener accepted LAN traffic at \(lanAddress):\(port)")
    } else {
        print("SKIP LAN refusal assertion: no active non-loopback IPv4 address")
    }

    let response = try udpExchange(host: "127.0.0.1", port: port, payload: dnsQuery(name: "regression.invalid"))
    try require(response.count >= 12, "silent-deny DNS response was truncated")
    try require(response[0] == 0x12 && response[1] == 0x34, "DNS response transaction ID changed")
    try require((response[2] & 0x80) != 0, "silent-deny DNS response was not marked as a response")
    try require((response[3] & 0x0f) == 3, "silent-deny DNS response was not NXDOMAIN")
    let stats = proxy.statistics
    try require(stats.queries == 1 && stats.blocked == 1 && stats.allowed == 0, "silent-deny statistics were incorrect")

    proxy.stop()
    try require(!proxy.running, "DNS proxy remained running after stop")

    let occupiedPort = try findAvailablePort(excluding: [port])
    let occupiedTCP = try withContext("occupy DNS test port") {
        try startGuardListener(using: .tcp, port: occupiedPort)
    }
    defer { occupiedTCP.cancel() }
    let conflicting = DNSProxy()
    let startedAt = Date()
    try requireThrows("DNS startup should fail when its TCP port is occupied") {
        try conflicting.start(port: occupiedPort)
    }
    try require(Date().timeIntervalSince(startedAt) < 6, "occupied-port startup did not fail within its bounded timeout")
    try require(!conflicting.running, "failed DNS startup reported running")

    let udpReleased = waitUntil(seconds: 2) {
        let result = processOutput(
            executable: "/usr/sbin/lsof",
            arguments: ["-nP", "-a", "-p", "\(getpid())", "-iUDP:\(occupiedPort)"]
        )
        return result.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
    try require(udpReleased, "failed DNS startup leaked its UDP listener")
    let releasedUDP = try startGuardListener(using: .udp, port: occupiedPort)
    releasedUDP.cancel()
}

private func testDNSProxyStartStopRace() throws {
    for iteration in 0..<20 {
        let port = try findAvailablePort()
        let proxy = DNSProxy()
        proxy.mode = .silentDeny
        let group = DispatchGroup()

        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            _ = try? proxy.start(port: port)
            group.leave()
        }
        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            proxy.stop()
            group.leave()
        }

        try require(
            group.wait(timeout: .now() + 6) == .success,
            "concurrent DNS start/stop did not finish at iteration \(iteration)"
        )
        proxy.stop()
        try require(!proxy.running, "concurrent DNS start/stop ended running at iteration \(iteration)")

        let released = waitUntil(seconds: 2) {
            let tcp = processOutput(
                executable: "/usr/sbin/lsof",
                arguments: ["-nP", "-a", "-p", "\(getpid())", "-iTCP:\(port)"]
            ).output
            let udp = processOutput(
                executable: "/usr/sbin/lsof",
                arguments: ["-nP", "-a", "-p", "\(getpid())", "-iUDP:\(port)"]
            ).output
            return tcp.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && udp.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        try require(released, "concurrent DNS start/stop leaked port \(port) at iteration \(iteration)")
    }
}

private func withTemporaryDirectory<T>(_ body: (URL) throws -> T) throws -> T {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("puresnitch-hardening-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    return try body(directory)
}

private func findAvailablePort(excluding excluded: Set<UInt16> = []) throws -> UInt16 {
    let lowerBound = 49_152
    let upperBound = 60_000
    let candidateCount = upperBound - lowerBound + 1
    let start = Int.random(in: lowerBound...upperBound)
    for offset in 0..<5_000 {
        let wrappedOffset = (start - lowerBound + offset) % candidateCount
        let candidate = UInt16(lowerBound + wrappedOffset)
        guard !excluded.contains(candidate) else { continue }
        let tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        let udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard tcp >= 0, udp >= 0 else {
            if tcp >= 0 { close(tcp) }
            if udp >= 0 { close(udp) }
            continue
        }
        var address = loopbackSocketAddress(port: candidate)
        let tcpBound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(tcp, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        let udpBound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(udp, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        close(tcp)
        close(udp)
        if tcpBound && udpBound { return candidate }
    }
    throw RegressionFailure(description: "could not find an unused high TCP+UDP port")
}

private func loopbackSocketAddress(port: UInt16) -> sockaddr_in {
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = in_port_t(port).bigEndian
    address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    return address
}

private func startGuardListener(using transport: NWParameters, port: UInt16) throws -> NWListener {
    guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
        throw RegressionFailure(description: "invalid guard-listener port \(port)")
    }
    transport.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: endpointPort)
    let listener = try NWListener(using: transport)
    let gate = ListenerGate()
    listener.stateUpdateHandler = { gate.update($0) }
    listener.newConnectionHandler = { $0.cancel() }
    listener.start(queue: DispatchQueue(label: "io.moamenbasel.puresnitch.tests.listener"))
    do {
        try gate.wait(seconds: 2)
        return listener
    } catch {
        listener.cancel()
        throw error
    }
}

private func tcpConnects(host: String, port: UInt16) -> Bool {
    guard let endpointPort = NWEndpoint.Port(rawValue: port) else { return false }
    let result = LockedBool()
    let semaphore = DispatchSemaphore(value: 0)
    let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: .tcp)
    connection.stateUpdateHandler = { state in
        switch state {
        case .ready:
            if result.setIfUnset(true) { semaphore.signal() }
        case .failed, .cancelled:
            if result.setIfUnset(false) { semaphore.signal() }
        default:
            break
        }
    }
    connection.start(queue: DispatchQueue(label: "io.moamenbasel.puresnitch.tests.tcp"))
    if semaphore.wait(timeout: .now() + 2) == .timedOut {
        _ = result.setIfUnset(false)
    }
    connection.cancel()
    return result.value ?? false
}

private func udpExchange(host: String, port: UInt16, payload: Data) throws -> Data {
    guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
        throw RegressionFailure(description: "invalid UDP port \(port)")
    }
    let semaphore = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var result: Result<Data, Error>?
    func finish(_ newResult: Result<Data, Error>) {
        lock.lock()
        if result == nil {
            result = newResult
            semaphore.signal()
        }
        lock.unlock()
    }

    let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: .udp)
    connection.stateUpdateHandler = { state in
        switch state {
        case .ready:
            connection.send(content: payload, completion: .contentProcessed { error in
                if let error {
                    finish(.failure(error))
                    return
                }
                connection.receiveMessage { data, _, _, error in
                    if let data {
                        finish(.success(data))
                    } else {
                        finish(.failure(error ?? RegressionFailure(description: "UDP reply was empty")))
                    }
                }
            })
        case .failed(let error):
            finish(.failure(error))
        default:
            break
        }
    }
    connection.start(queue: DispatchQueue(label: "io.moamenbasel.puresnitch.tests.udp"))
    guard semaphore.wait(timeout: .now() + 3) == .success else {
        connection.cancel()
        throw RegressionFailure(description: "timed out waiting for UDP DNS response")
    }
    connection.cancel()
    lock.lock()
    let resolved = result
    lock.unlock()
    return try resolved?.get() ?? { throw RegressionFailure(description: "UDP exchange completed without a result") }()
}

private func dnsQuery(name: String) -> Data {
    var query = Data([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    for label in name.split(separator: ".") {
        query.append(UInt8(label.utf8.count))
        query.append(contentsOf: label.utf8)
    }
    query.append(0)
    query.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
    return query
}

private func firstNonLoopbackIPv4() -> String? {
    var first: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&first) == 0, let first else { return nil }
    defer { freeifaddrs(first) }

    var current: UnsafeMutablePointer<ifaddrs>? = first
    while let pointer = current {
        let interface = pointer.pointee
        defer { current = interface.ifa_next }
        guard let address = interface.ifa_addr,
              address.pointee.sa_family == UInt8(AF_INET),
              (interface.ifa_flags & UInt32(IFF_UP)) != 0 else { continue }
        let name = String(cString: interface.ifa_name)
        guard name != "lo0" else { continue }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let status = getnameinfo(
            address,
            socklen_t(address.pointee.sa_len),
            &host,
            socklen_t(host.count),
            nil,
            0,
            NI_NUMERICHOST
        )
        guard status == 0 else { continue }
        let value = String(cString: host)
        if value != "127.0.0.1" && !value.hasPrefix("169.254.") { return value }
    }
    return nil
}

private func processOutput(executable: String, arguments: [String]) -> (status: Int32, output: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    do {
        try process.run()
    } catch {
        return (-1, error.localizedDescription)
    }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
}

private func waitUntil(seconds: TimeInterval, predicate: () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    repeat {
        if predicate() { return true }
        Thread.sleep(forTimeInterval: 0.05)
    } while Date() < deadline
    return predicate()
}

@main
private enum HardeningRegression {
    static func main() {
        let tests: [(String, () throws -> Void)] = [
            ("rule validation and matching", testRuleValidationAndMatching),
            ("HelperStatus compatibility", testHelperStatusCompatibility),
            ("helper security state", testHelperSecurityState),
            ("helper outbound authorization integration", testHelperServiceAuthorizationIntegration),
            ("legacy helper upgrade sequencing", testLegacyHelperUpgradeSequencing),
            ("helper recovery and status freshness", testHelperClientRecoveryAndStatusFreshness),
            ("helper legacy reconciliation integration", testHelperLegacyReconciliationIntegration),
            ("database restore", testDatabaseRestore),
            ("connection history retention", testConnectionHistoryRetention),
            ("pending DNS asks", testPendingDNSAsks),
            ("standalone PF cleanup gate", testStandalonePFCleanupGate),
            ("PF legacy reconciliation health", testPFLegacyReconciliationHealth),
            ("PF lifecycle and rendering", testPFManagerLifecycleAndRendering),
            ("DNS loopback isolation and cleanup", testDNSProxyIsolationAndCleanup),
            ("DNS start/stop race", testDNSProxyStartStopRace),
        ]

        var failures: [String] = []
        for (name, test) in tests {
            do {
                try test()
                print("PASS \(name)")
            } catch {
                failures.append("FAIL \(name): \(error)")
            }
        }
        guard failures.isEmpty else {
            for failure in failures { fputs(failure + "\n", stderr) }
            exit(1)
        }
        print("PASS all hardening regression checks")
    }
}
