import Foundation
import Darwin

final class PFManager: @unchecked Sendable {
    typealias CommandRunner = (_ executable: String, _ arguments: [String]) throws -> String
    typealias DaemonAbsenceChecker = () throws -> Void

    static let anchorName = "com.apple/puresnitch"
    private static let parentAnchorName = "com.apple/*"
    private static let legacyAnchorName = "puresnitch"
    private let anchorPath: String
    private let enableTokenPath: String
    private let processLockPath: String
    private let legacyAnchorPath: String
    private let legacyPFConfPath: String
    private let pfctl = "/sbin/pfctl"
    private let queue = DispatchQueue(label: "io.moamenbasel.puresnitch.pf")
    private let commandRunner: CommandRunner?
    private let daemonAbsenceChecker: DaemonAbsenceChecker
    private var loaded: Bool
    private var legacyReconciliationSucceeded: Bool?

    private struct CurrentCleanupResult {
        let failures: [String]
        let runtimeCleared: Bool
    }

    init(
        commandRunner: CommandRunner? = nil,
        initiallyLoaded: Bool = false,
        anchorPath: String = "/Library/Application Support/PureSnitch/pf-anchor.conf",
        enableTokenPath: String = "/var/run/puresnitch.pf-token",
        processLockPath: String = "/var/run/puresnitch.pf.lock",
        legacyAnchorPath: String = "/etc/pf.anchors/puresnitch",
        legacyPFConfPath: String = "/etc/pf.conf",
        daemonAbsenceChecker: DaemonAbsenceChecker? = nil
    ) {
        self.commandRunner = commandRunner
        self.anchorPath = anchorPath
        self.enableTokenPath = enableTokenPath
        self.processLockPath = processLockPath
        self.legacyAnchorPath = legacyAnchorPath
        self.legacyPFConfPath = legacyPFConfPath
        self.daemonAbsenceChecker = daemonAbsenceChecker ?? {
            try HelperDaemonCleanupGate.requireStopped(serviceLabel: AppConstants.xpcMachServiceName)
        }
        // A surviving token means a previous helper instance may still own an
        // active PF reference. Report the conservative state until checked.
        self.loaded = initiallyLoaded || FileManager.default.fileExists(atPath: enableTokenPath)
        self.legacyReconciliationSucceeded = nil
    }

    func install(rules: [Rule] = []) throws {
        try withProcessLock {
            try queue.sync {
                try throwIfFailures(cleanupLegacyStateLocked(), operation: "legacy PF cleanup")
                try ensureParentAnchorIsActive()
                try writeAnchorFile(rules: rules)
                try ensureEnableReference()
                do {
                    try loadAnchor()
                    loaded = true
                } catch {
                    // A token or partially loaded subanchor may now exist. Keep the
                    // state conservative so the caller performs checked rollback.
                    loaded = true
                    throw error
                }
            }
        }
    }

    /// Stage current deny rules while leaving a detected legacy anchor intact.
    /// The caller starts DNS and then invokes reconcileLegacyState(), so an
    /// activation failure cannot create a fail-open migration window.
    func installCurrentStatePreservingLegacy(rules: [Rule]) throws {
        try withProcessLock {
            try queue.sync {
                legacyReconciliationSucceeded = nil
                try ensureParentAnchorIsActive()
                try writeAnchorFile(rules: rules)
                try ensureEnableReference()
                do {
                    try loadAnchor()
                    loaded = true
                } catch {
                    loaded = true
                    throw error
                }
            }
        }
    }

    func reconcileLegacyState() throws {
        try withProcessLock {
            try queue.sync {
                try throwIfFailures(cleanupLegacyStateLocked(), operation: "legacy PF cleanup")
            }
        }
    }

    /// Roll back only the newly-staged current anchor. Legacy enforcement is
    /// intentionally preserved when DNS/current activation fails before the
    /// migration decision can be completed.
    func uninstallCurrentStatePreservingLegacy() throws {
        try withProcessLock {
            try queue.sync {
                let current = cleanupCurrentStateLocked(releaseToken: true)
                loaded = !current.runtimeCleared
                guard current.failures.isEmpty else {
                    throw NSError(
                        domain: "PFManager",
                        code: 16,
                        userInfo: [NSLocalizedDescriptionKey: current.failures.joined(separator: "; ")]
                    )
                }
                loaded = false
            }
        }
    }

    func uninstall() throws {
        try withProcessLock {
            try queue.sync {
                var failures = cleanupLegacyStateLocked()
                let current = cleanupCurrentStateLocked(releaseToken: true)
                failures.append(contentsOf: current.failures)
                // Legacy v0.2 migration degradation is reported, but must not
                // make the GUI claim the current com.apple/puresnitch rules are
                // active after their checked flush/unload succeeded.
                loaded = !current.runtimeCleared
                guard failures.isEmpty else {
                    throw NSError(
                        domain: "PFManager",
                        code: 2,
                        userInfo: [NSLocalizedDescriptionKey: failures.joined(separator: "; ")]
                    )
                }
                loaded = false
            }
        }
    }

    /// Remove stale state before the XPC service starts accepting clients. A
    /// stored token belongs only to PureSnitch and is safe to release; unknown
    /// legacy enable references are deliberately left alone.
    func cleanupOrphanedState() throws {
        try withProcessLock {
            try queue.sync {
                try cleanupOrphanedStateLocked()
            }
        }
    }

    /// Standalone Homebrew/uninstall cleanup must not mutate PF while the
    /// launchd daemon is alive. The absence check runs while holding the same
    /// cross-process PF lock used by startup/install, closing the check/use gap.
    func cleanupOrphanedStateForStandaloneProcess() throws {
        try withProcessLock {
            try queue.sync {
                try daemonAbsenceChecker()
                try cleanupOrphanedStateLocked()
            }
        }
    }

    var isLoaded: Bool { queue.sync { loaded } }
    var latestLegacyReconciliationSucceeded: Bool? {
        queue.sync { legacyReconciliationSucceeded }
    }

    /// Read-only migration probe. Legacy rules are deliberately left untouched
    /// until a caller with no persisted enforcement intent chooses on or off.
    func hasLegacyState() throws -> Bool {
        try withProcessLock {
            try queue.sync { try legacyStatePresentLocked() }
        }
    }

    func applyRules(_ rules: [Rule]) throws {
        try withProcessLock {
            try queue.sync {
                guard loaded else {
                    throw NSError(
                        domain: "PFManager",
                        code: 8,
                        userInfo: [NSLocalizedDescriptionKey: "PF enforcement is not enabled"]
                    )
                }
                try writeAnchorFile(rules: rules)
                try loadAnchor()
            }
        }
    }

    private func loadAnchor() throws {
        try run(pfctl, ["-a", PFManager.anchorName, "-nf", anchorPath])
        try run(pfctl, ["-a", PFManager.anchorName, "-f", anchorPath])
        try run(pfctl, ["-a", PFManager.anchorName, "-sr"])
    }

    private func writeAnchorFile(rules: [Rule]) throws {
        var lines: [String] = []
        lines.append("# PureSnitch pf anchor - auto-generated. Do not edit.")

        let now = Date()
        let denyRules = rules.filter {
            $0.action == .deny && $0.enabled && $0.profile == "default"
                && ($0.expiresAt.map { $0 > now } ?? true)
        }

        for r in denyRules {
            lines.append(contentsOf: pfLines(rule: r))
        }

        let content = lines.joined(separator: "\n") + "\n"
        try content.write(toFile: anchorPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: anchorPath)
    }

    private func pfLines(rule r: Rule) -> [String] {
        let processName = r.processName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if r.scope == .process
            || !(r.processBundleId?.isEmpty ?? true)
            || !(r.processPath?.isEmpty ?? true)
            || (!processName.isEmpty && processName.caseInsensitiveCompare("Any Process") != .orderedSame) {
            PSLog.info(PSLog.pf, "omitting process-scoped rule \(r.id) from global pf anchor")
            return []
        }
        guard r.scope == .ip || r.scope == .port || r.scope == .any else {
            PSLog.info(PSLog.pf, "omitting non-IP rule \(r.id) from pf anchor")
            return []
        }

        let networkToken: String?
        if let rawIP = r.remoteIP, !rawIP.isEmpty {
            guard let canonical = canonicalNetworkToken(rawIP) else {
                PSLog.error(PSLog.pf, "omitting rule \(r.id): invalid remote IP token")
                return []
            }
            networkToken = canonical
        } else if let rawHost = r.remoteHost, !rawHost.isEmpty {
            // pf resolves hostnames while loading its config. Besides changing
            // semantics as DNS changes, interpolating an arbitrary hostname into
            // a root-written anchor is unsafe. DNS-name rules stay in DNSProxy;
            // only a strict IP/CIDR token is eligible for pf.
            guard let canonical = canonicalNetworkToken(rawHost) else {
                PSLog.info(PSLog.pf, "omitting domain-only rule \(r.id) from pf anchor")
                return []
            }
            networkToken = canonical
        } else {
            networkToken = nil
        }

        if let port = r.remotePort, !(0...65_535).contains(port) {
            PSLog.error(PSLog.pf, "omitting rule \(r.id): invalid remote port")
            return []
        }

        if networkToken == nil && (r.remotePort ?? 0) == 0 {
            return []
        }

        func line(direction: String, endpointKeyword: String) -> String {
            var value = "block \(direction) quick proto { tcp udp } \(endpointKeyword) "
            value += networkToken ?? "any"
            if let port = r.remotePort, port > 0 { value += " port \(port)" }
            return value
        }
        switch r.direction {
        case .outgoing:
            return [line(direction: "out", endpointKeyword: "to")]
        case .incoming:
            return [line(direction: "in", endpointKeyword: "from")]
        case .any:
            return [
                line(direction: "out", endpointKeyword: "to"),
                line(direction: "in", endpointKeyword: "from"),
            ]
        }
    }

    private func canonicalNetworkToken(_ raw: String) -> String? {
        Rule.isValidRemoteIP(raw) ? raw : nil
    }

    private func ensureParentAnchorIsActive() throws {
        let rules = try run(pfctl, ["-sr"])
        let declaration = "anchor \"\(PFManager.parentAnchorName)\""
        let isActive = rules.split(whereSeparator: \.isNewline).contains { line in
            line.trimmingCharacters(in: .whitespaces).hasPrefix(declaration)
        }
        guard isActive else {
            throw NSError(
                domain: "PFManager",
                code: 9,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "the active PF ruleset does not expose the required com.apple/* parent anchor"
                ]
            )
        }
    }

    private func cleanupCurrentStateLocked(releaseToken: Bool) -> CurrentCleanupResult {
        var failures: [String] = []
        do {
            try writeAnchorFile(rules: [])
        } catch {
            failures.append("clear PureSnitch anchor file: \(error.localizedDescription)")
        }

        let operations: [(String, [String])] = [
            ("flush PureSnitch runtime rules", ["-a", PFManager.anchorName, "-F", "rules"]),
            ("unload PureSnitch runtime anchor", ["-a", PFManager.anchorName, "-f", "/dev/null"]),
        ]
        var runtimeOperationsSucceeded = true
        for (description, arguments) in operations {
            do {
                try runCleanupCommand(arguments)
            } catch {
                runtimeOperationsSucceeded = false
                failures.append("\(description): \(error.localizedDescription)")
            }
        }

        // Never release our PF reference if clearing rules failed: retaining
        // the token keeps state observable and allows a truthful retry.
        if releaseToken && failures.isEmpty {
            do {
                try releaseEnableReference()
            } catch {
                failures.append("release pf enable reference: \(error.localizedDescription)")
            }
        }
        return CurrentCleanupResult(
            failures: failures,
            runtimeCleared: runtimeOperationsSucceeded
        )
    }

    private func cleanupOrphanedStateLocked() throws {
        var failures = cleanupLegacyStateLocked()
        let current = cleanupCurrentStateLocked(releaseToken: true)
        failures.append(contentsOf: current.failures)
        loaded = !current.runtimeCleared
        guard failures.isEmpty else {
            throw NSError(
                domain: "PFManager",
                code: 7,
                userInfo: [NSLocalizedDescriptionKey: failures.joined(separator: "; ")]
            )
        }
        loaded = false
    }

    private func cleanupLegacyStateLocked() -> [String] {
        var failures: [String] = []
        do {
            try removeLegacyPFDeclarations()
        } catch {
            failures.append("remove legacy pf.conf declarations: \(error.localizedDescription)")
        }

        var legacyAnchorWasPresent = false
        do {
            legacyAnchorWasPresent = try regularFileContentsIfPresent(at: legacyAnchorPath) != nil
        } catch {
            failures.append("inspect legacy anchor file: \(error.localizedDescription)")
        }

        if legacyAnchorWasPresent {
            do {
                try writeEmptyAnchorFile(at: legacyAnchorPath)
            } catch {
                failures.append("clear legacy anchor file: \(error.localizedDescription)")
            }
        }

        let operations: [(String, [String])] = [
            ("flush legacy runtime rules", ["-a", PFManager.legacyAnchorName, "-F", "rules"]),
            ("unload legacy runtime anchor", ["-a", PFManager.legacyAnchorName, "-f", "/dev/null"]),
        ]
        for (description, arguments) in operations {
            do {
                try runCleanupCommand(arguments)
            } catch {
                failures.append("\(description): \(error.localizedDescription)")
            }
        }

        // The empty file is retained whenever any preceding step failed. It is
        // both fail-closed retry evidence and an uninstall-gate signal. Only a
        // completely checked cleanup removes the obsolete legacy artifact.
        if failures.isEmpty && legacyAnchorWasPresent {
            do {
                try removeClearedLegacyAnchorFile()
            } catch {
                failures.append("remove cleared legacy anchor file: \(error.localizedDescription)")
            }
        }
        legacyReconciliationSucceeded = failures.isEmpty
        return failures
    }

    private func legacyStatePresentLocked() throws -> Bool {
        if let pfConf = try regularFileContentsIfPresent(at: legacyPFConfPath) {
            let declarations: Set<String> = [
                "anchor \"puresnitch\"",
                "load anchor \"puresnitch\" from \"/etc/pf.anchors/puresnitch\"",
            ]
            if pfConf.split(whereSeparator: \.isNewline).contains(where: { line in
                declarations.contains(line.trimmingCharacters(in: .whitespaces))
            }) {
                return true
            }
        }

        if let anchor = try regularFileContentsIfPresent(at: legacyAnchorPath),
           anchor.split(whereSeparator: \.isNewline).contains(where: { line in
               let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
               return !trimmed.isEmpty && !trimmed.hasPrefix("#")
           }) {
            return true
        }

        do {
            let runtimeRules = try run(pfctl, ["-a", PFManager.legacyAnchorName, "-sr"])
            return runtimeRules.split(whereSeparator: \.isNewline).contains { line in
                guard let keyword = line.split(whereSeparator: \.isWhitespace).first else { return false }
                return ["block", "pass", "match", "anchor"].contains(keyword.lowercased())
            }
        } catch {
            if error.localizedDescription.localizedCaseInsensitiveContains("pf not enabled") {
                return false
            }
            throw error
        }
    }

    private func regularFileContentsIfPresent(at path: String) throws -> String? {
        var info = stat()
        guard lstat(path, &info) == 0 else {
            if errno == ENOENT { return nil }
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "could not inspect legacy PF state"]
            )
        }
        guard info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else {
            throw NSError(
                domain: "PFManager",
                code: 15,
                userInfo: [NSLocalizedDescriptionKey: "legacy PF state path is not a regular file"]
            )
        }
        return try String(contentsOfFile: path, encoding: .utf8)
    }

    private func removeLegacyPFDeclarations() throws {
        let original = try String(contentsOfFile: legacyPFConfPath, encoding: .utf8)
        let legacyLines: Set<String> = [
            "anchor \"puresnitch\"",
            "load anchor \"puresnitch\" from \"/etc/pf.anchors/puresnitch\"",
        ]
        let originalLines = original.components(separatedBy: "\n")
        let filteredLines = originalLines.filter {
            !legacyLines.contains($0.trimmingCharacters(in: .whitespaces))
        }
        guard filteredLines.count != originalLines.count else { return }
        let candidate = filteredLines.joined(separator: "\n")

        let liveURL = URL(fileURLWithPath: legacyPFConfPath)
        let temporaryURL = liveURL.deletingLastPathComponent()
            .appendingPathComponent(".pf.conf.puresnitch-\(UUID().uuidString).tmp")
        defer { try? FileManager.default.removeItem(at: temporaryURL) }
        // Clone the live file first so flags, ACLs and extended attributes are
        // carried to the replacement. Writing a fresh temporary file and asking
        // Foundation to preserve metadata drops macOS flags such as compressed.
        try FileManager.default.copyItem(at: liveURL, to: temporaryURL)
        let originalAttributes = try FileManager.default.attributesOfItem(atPath: legacyPFConfPath)
        let originalFlags = try fileFlags(atPath: legacyPFConfPath)
        let handle = try FileHandle(forWritingTo: temporaryURL)
        do {
            try handle.truncate(atOffset: 0)
            try handle.write(contentsOf: Data(candidate.utf8))
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            throw error
        }
        let temporaryAttributes = try FileManager.default.attributesOfItem(atPath: temporaryURL.path)
        for key in [FileAttributeKey.posixPermissions, .ownerAccountID, .groupOwnerAccountID] {
            let expected = (originalAttributes[key] as? NSNumber)?.uint64Value
            let actual = (temporaryAttributes[key] as? NSNumber)?.uint64Value
            guard expected == actual else {
                throw NSError(
                    domain: "PFManager",
                    code: 13,
                    userInfo: [NSLocalizedDescriptionKey: "pf.conf temporary ownership or mode changed during migration"]
                )
            }
        }
        guard try securityRelevantFileFlags(atPath: temporaryURL.path)
            == (originalFlags & ~UInt32(UF_COMPRESSED)) else {
            throw NSError(
                domain: "PFManager",
                code: 14,
                userInfo: [NSLocalizedDescriptionKey: "pf.conf temporary file flags changed during migration"]
            )
        }
        try run(pfctl, ["-nf", temporaryURL.path])

        let current = try String(contentsOfFile: legacyPFConfPath, encoding: .utf8)
        guard current == original else {
            throw NSError(
                domain: "PFManager",
                code: 10,
                userInfo: [NSLocalizedDescriptionKey: "pf.conf changed while legacy cleanup was being validated"]
            )
        }
        _ = try FileManager.default.replaceItemAt(
            liveURL,
            withItemAt: temporaryURL,
            backupItemName: nil,
            options: .usingNewMetadataOnly
        )

        let installed = try String(contentsOfFile: legacyPFConfPath, encoding: .utf8)
        guard installed == candidate else {
            throw NSError(
                domain: "PFManager",
                code: 12,
                userInfo: [NSLocalizedDescriptionKey: "pf.conf content did not match the validated migration candidate"]
            )
        }
        let installedAttributes = try FileManager.default.attributesOfItem(atPath: legacyPFConfPath)
        for key in [FileAttributeKey.posixPermissions, .ownerAccountID, .groupOwnerAccountID] {
            let expected = (originalAttributes[key] as? NSNumber)?.uint64Value
            let actual = (installedAttributes[key] as? NSNumber)?.uint64Value
            guard expected == actual else {
                throw NSError(
                    domain: "PFManager",
                    code: 13,
                    userInfo: [NSLocalizedDescriptionKey: "pf.conf ownership or mode changed during migration"]
                )
            }
        }
        // Rewriting file contents legitimately clears UF_COMPRESSED. Compare
        // every other flag so security-relevant immutable/append flags cannot
        // be lost silently.
        guard try securityRelevantFileFlags(atPath: legacyPFConfPath)
            == (originalFlags & ~UInt32(UF_COMPRESSED)) else {
            throw NSError(
                domain: "PFManager",
                code: 14,
                userInfo: [NSLocalizedDescriptionKey: "pf.conf file flags changed during migration"]
            )
        }
    }

    private func fileFlags(atPath path: String) throws -> UInt32 {
        var info = stat()
        guard lstat(path, &info) == 0 else {
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "could not inspect pf.conf metadata"]
            )
        }
        return info.st_flags
    }

    private func securityRelevantFileFlags(atPath path: String) throws -> UInt32 {
        try fileFlags(atPath: path) & ~UInt32(UF_COMPRESSED)
    }

    private func writeEmptyAnchorFile(at path: String) throws {
        try "# PureSnitch legacy anchor cleared during migration.\n"
            .write(toFile: path, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    }

    private func removeClearedLegacyAnchorFile() throws {
        let expected = "# PureSnitch legacy anchor cleared during migration.\n"
        guard try regularFileContentsIfPresent(at: legacyAnchorPath) == expected else {
            throw NSError(
                domain: "PFManager",
                code: 17,
                userInfo: [NSLocalizedDescriptionKey: "legacy anchor changed before removal"]
            )
        }
        try FileManager.default.removeItem(atPath: legacyAnchorPath)
    }

    private func runCleanupCommand(_ arguments: [String]) throws {
        do {
            try run(pfctl, arguments)
        } catch {
            if error.localizedDescription.localizedCaseInsensitiveContains("pf not enabled") { return }
            throw error
        }
    }

    private func throwIfFailures(_ failures: [String], operation: String) throws {
        guard failures.isEmpty else {
            throw NSError(
                domain: "PFManager",
                code: 11,
                userInfo: [NSLocalizedDescriptionKey: "\(operation): " + failures.joined(separator: "; ")]
            )
        }
    }

    private func withProcessLock<T>(_ body: () throws -> T) throws -> T {
        let descriptor = open(processLockPath, O_CREAT | O_RDWR, mode_t(0o600))
        guard descriptor >= 0 else {
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "could not open the PureSnitch PF lifecycle lock"]
            )
        }
        defer { close(descriptor) }
        guard fchmod(descriptor, mode_t(0o600)) == 0 else {
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "could not secure the PureSnitch PF lifecycle lock"]
            )
        }
        guard flock(descriptor, LOCK_EX) == 0 else {
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "could not acquire the PureSnitch PF lifecycle lock"]
            )
        }
        defer { flock(descriptor, LOCK_UN) }
        return try body()
    }

    /// `pfctl -E` is reference counted. Persist the token so a helper restart
    /// reuses the same reference instead of leaking another one.
    private func ensureEnableReference() throws {
        if let existingToken = try storedEnableToken() {
            let references = try run(pfctl, ["-s", "References"])
            if referencesContain(token: existingToken, output: references) { return }
            try FileManager.default.removeItem(atPath: enableTokenPath)
        }

        let output = try run(pfctl, ["-E"])
        guard let token = parseEnableToken(output) else {
            throw NSError(
                domain: "PFManager",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "pf was enabled but pfctl did not return a releasable token"]
            )
        }

        do {
            try (token + "\n").write(toFile: enableTokenPath, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: enableTokenPath)
        } catch {
            let persistenceError = error
            do {
                try run(pfctl, ["-X", token])
                try? FileManager.default.removeItem(atPath: enableTokenPath)
            } catch let releaseError {
                throw NSError(
                    domain: "PFManager",
                    code: 4,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "could not persist pf enable token: \(persistenceError.localizedDescription); "
                            + "releasing the new reference also failed: \(releaseError.localizedDescription)"
                    ]
                )
            }
            throw persistenceError
        }
    }

    private func releaseEnableReference() throws {
        guard let token = try storedEnableToken() else { return }
        let references = try run(pfctl, ["-s", "References"])
        guard referencesContain(token: token, output: references) else {
            try FileManager.default.removeItem(atPath: enableTokenPath)
            return
        }
        do {
            try run(pfctl, ["-X", token])
        } catch {
            // `pfctl -X` may have released the reference before the caller saw
            // an error. Recheck so a stale token file cannot wedge all future
            // cleanup attempts.
            let refreshedReferences = try run(pfctl, ["-s", "References"])
            guard !referencesContain(token: token, output: refreshedReferences) else { throw error }
        }
        try FileManager.default.removeItem(atPath: enableTokenPath)
    }

    private func storedEnableToken() throws -> String? {
        guard FileManager.default.fileExists(atPath: enableTokenPath) else { return nil }
        let raw = try String(contentsOfFile: enableTokenPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let token = UInt64(raw), token > 0, String(token) == raw else {
            throw NSError(
                domain: "PFManager",
                code: 5,
                userInfo: [NSLocalizedDescriptionKey: "stored pf enable token is invalid"]
            )
        }
        return raw
    }

    private func parseEnableToken(_ output: String) -> String? {
        guard let marker = output.range(of: "Token :") else { return nil }
        let suffix = output[marker.upperBound...].drop(while: { $0.isWhitespace })
        let digits = suffix.prefix(while: { $0.isNumber })
        guard let token = UInt64(digits), token > 0 else { return nil }
        return String(token)
    }

    private func referencesContain(token: String, output: String) -> Bool {
        output.split(whereSeparator: \.isNewline).contains { line in
            let fields = line.split(whereSeparator: \.isWhitespace)
            return fields.count >= 3 && fields[2] == token
        }
    }

    @discardableResult
    private func run(_ exec: String, _ args: [String]) throws -> String {
        if let commandRunner { return try commandRunner(exec, args) }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: exec)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let output = String(data: data, encoding: .utf8) ?? ""
        if p.terminationStatus != 0 {
            let category = commandCategory(args)
            PSLog.error(
                PSLog.pf,
                "pfctl command failed category=\(category) rc=\(p.terminationStatus)"
            )
            let description = args.first == "-X"
                ? "pfctl release-reference failed (rc \(p.terminationStatus))"
                : output
            throw NSError(
                domain: "PFManager",
                code: Int(p.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: description]
            )
        }
        return output
    }

    private func commandCategory(_ arguments: [String]) -> String {
        if arguments.first == "-X" { return "release-reference" }
        if arguments.contains("-E") { return "acquire-reference" }
        if arguments.contains("-F") { return "flush-anchor" }
        if arguments.contains("-nf") { return "validate-rules" }
        if arguments.contains("-f") { return "load-anchor" }
        if arguments.contains("-sr") { return "list-rules" }
        return "other"
    }
}
