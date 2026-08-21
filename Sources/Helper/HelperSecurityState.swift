import Foundation
import Darwin
import SQLite3

enum HelperSecurityStateError: Error, LocalizedError {
    case invalidDesiredSetting
    case invalidOwnerSetting
    case unsafePath(String)
    case invalidDatabaseBackup(String)

    var errorDescription: String? {
        switch self {
        case .invalidDesiredSetting:
            return "the persisted enforcement setting is invalid"
        case .invalidOwnerSetting:
            return "the persisted helper owner UID is invalid"
        case .unsafePath(let path):
            return "unsafe helper storage path: \(path)"
        case .invalidDatabaseBackup(let reason):
            return "invalid PureSnitch database backup: \(reason)"
        }
    }
}

enum HelperDaemonCleanupGateError: Error, LocalizedError {
    case daemonIsRunning
    case daemonStateUnknown(Int32?)

    var errorDescription: String? {
        switch self {
        case .daemonIsRunning:
            return "the PureSnitch helper daemon is still running"
        case .daemonStateUnknown(let status):
            if let status {
                return "could not verify that the PureSnitch helper daemon is stopped (launchctl rc \(status))"
            }
            return "could not verify that the PureSnitch helper daemon is stopped"
        }
    }
}

enum HelperDaemonCleanupGate {
    enum CommandResult: Equatable {
        case exited(Int32)
        case signaled(Int32)
    }

    typealias CommandRunner = (_ serviceTarget: String) throws -> CommandResult
    private static let serviceNotFoundExitStatus: Int32 = 113

    static func requireStopped(
        serviceLabel: String,
        commandRunner: CommandRunner? = nil
    ) throws {
        let target = "system/\(serviceLabel)"
        let result = try (commandRunner ?? runLaunchctlPrint)(target)
        switch result {
        case .exited(0):
            throw HelperDaemonCleanupGateError.daemonIsRunning
        case .exited(serviceNotFoundExitStatus):
            return
        case .exited(let status):
            throw HelperDaemonCleanupGateError.daemonStateUnknown(status)
        case .signaled:
            throw HelperDaemonCleanupGateError.daemonStateUnknown(nil)
        }
    }

    private static func runLaunchctlPrint(serviceTarget: String) throws -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["print", serviceTarget]
        // Service descriptions can contain environment values. Cleanup only
        // needs launchctl's exit status, so never capture or log its output.
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        switch process.terminationReason {
        case .exit:
            return .exited(process.terminationStatus)
        case .uncaughtSignal:
            return .signaled(process.terminationStatus)
        @unknown default:
            return .signaled(process.terminationStatus)
        }
    }
}

enum HelperSecurityState {
    static let desiredSettingKey = "enforcement_desired"
    static let ownerUIDSettingKey = "owner_uid"
    static let legacyPFMigrationPendingSettingKey = "legacy_pf_migration_pending"
    static let legacyPFReconciliationSettingKey = "legacy_pf_reconciliation_succeeded"
    static let maximumDatabaseRestoreBytes: Int64 = 2 * 1_024 * 1_024 * 1_024

    enum DatabaseRestoreResult: Equatable {
        case sourceMissing
        case targetAlreadyExists
        case restored
    }

    static func decodeDesired(_ raw: String?) throws -> Bool {
        switch raw {
        case nil, "", "0": return false
        case "1": return true
        default: throw HelperSecurityStateError.invalidDesiredSetting
        }
    }

    static func encodeDesired(_ desired: Bool) -> String { desired ? "1" : "0" }

    static func decodeOwnerUID(_ raw: String?) throws -> uid_t? {
        guard let raw, !raw.isEmpty else { return nil }
        guard let parsed = UInt32(raw), parsed != 0, String(parsed) == raw else {
            throw HelperSecurityStateError.invalidOwnerSetting
        }
        return uid_t(parsed)
    }

    static func encodeOwnerUID(_ uid: uid_t) throws -> String {
        guard uid != 0 else { throw HelperSecurityStateError.invalidOwnerSetting }
        return String(uid)
    }

    static func consoleUID(consolePath: String = "/dev/console") -> uid_t? {
        var info = stat()
        guard lstat(consolePath, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFCHR) else { return nil }
        return info.st_uid
    }

    static func isAdmin(uid: uid_t) -> Bool {
        guard let user = getpwuid(uid), let admin = getgrnam("admin") else { return false }
        if user.pointee.pw_gid == admin.pointee.gr_gid { return true }

        let baseGID = Int32(bitPattern: user.pointee.pw_gid)
        let adminGID = Int32(bitPattern: admin.pointee.gr_gid)
        var capacity: Int32 = 64
        while capacity <= 1_024 {
            var count = capacity
            var groups = [Int32](repeating: 0, count: Int(capacity))
            let result = groups.withUnsafeMutableBufferPointer { buffer in
                getgrouplist(user.pointee.pw_name, baseGID, buffer.baseAddress, &count)
            }
            if result >= 0 {
                return groups.prefix(Int(count)).contains(adminGID)
            }
            capacity = count > capacity ? count : capacity * 2
        }
        return false
    }

    static func prepareSupportDirectory(at path: String, expectedOwnerUID: uid_t = 0) throws {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        try secureExistingPath(
            path,
            expectedType: mode_t(S_IFDIR),
            permissions: 0o700,
            expectedOwnerUID: expectedOwnerUID
        )
    }

    static func validateDatabasePathBeforeOpen(_ databasePath: String, expectedOwnerUID: uid_t = 0) throws {
        guard try pathExistsIncludingSymlink(databasePath) else { return }
        try secureExistingPath(
            databasePath,
            expectedType: mode_t(S_IFREG),
            permissions: 0o600,
            expectedOwnerUID: expectedOwnerUID
        )
    }

    static func hardenDatabaseFiles(_ databasePath: String, expectedOwnerUID: uid_t = 0) throws {
        for path in [databasePath, databasePath + "-wal", databasePath + "-shm"] {
            guard try pathExistsIncludingSymlink(path) else { continue }
            try secureExistingPath(
                path,
                expectedType: mode_t(S_IFREG),
                permissions: 0o600,
                expectedOwnerUID: expectedOwnerUID
            )
        }
    }

    /// Restore a Homebrew migration backup without ever overwriting an existing
    /// helper database. The copy is created in the target directory, validated
    /// there, and linked into place atomically with EEXIST protection.
    static func restoreDatabase(
        sourcePath: String,
        targetPath: String,
        allowedSourceOwnerUIDs: Set<uid_t>,
        targetOwnerUID: uid_t = 0,
        maximumBytes: Int64 = maximumDatabaseRestoreBytes
    ) throws -> DatabaseRestoreResult {
        if try pathExistsIncludingSymlink(targetPath) {
            try secureExistingPath(
                targetPath,
                expectedType: mode_t(S_IFREG),
                permissions: 0o600,
                expectedOwnerUID: targetOwnerUID
            )
            try validateSQLiteDatabase(at: targetPath)
            return .targetAlreadyExists
        }

        var sourceInfo = stat()
        guard lstat(sourcePath, &sourceInfo) == 0 else {
            if errno == ENOENT { return .sourceMissing }
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        guard sourceInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              allowedSourceOwnerUIDs.contains(sourceInfo.st_uid),
              sourceInfo.st_size > 0,
              maximumBytes > 0,
              sourceInfo.st_size <= maximumBytes else {
            throw HelperSecurityStateError.invalidDatabaseBackup("unsafe source type, owner, or size")
        }
        for sidecar in [sourcePath + "-wal", sourcePath + "-shm"]
        where try pathExistsIncludingSymlink(sidecar) {
            throw HelperSecurityStateError.invalidDatabaseBackup(
                "backup is not a standalone SQLite snapshot"
            )
        }

        let targetURL = URL(fileURLWithPath: targetPath)
        let temporaryURL = targetURL.deletingLastPathComponent()
            .appendingPathComponent(".puresnitch-restore-\(UUID().uuidString).sqlite")
        defer { try? FileManager.default.removeItem(at: temporaryURL) }

        try copyRegularFile(
            sourcePath: sourcePath,
            destinationPath: temporaryURL.path,
            allowedSourceOwnerUIDs: allowedSourceOwnerUIDs,
            targetOwnerUID: targetOwnerUID,
            maximumBytes: maximumBytes
        )
        try validateSQLiteDatabase(at: temporaryURL.path, normalizeStandaloneCopy: true)
        for sidecar in [temporaryURL.path + "-wal", temporaryURL.path + "-shm"] {
            if try pathExistsIncludingSymlink(sidecar) {
                try FileManager.default.removeItem(atPath: sidecar)
            }
        }
        try secureExistingPath(
            temporaryURL.path,
            expectedType: mode_t(S_IFREG),
            permissions: 0o600,
            expectedOwnerUID: targetOwnerUID
        )

        // Hard-linking within one directory is atomic and, unlike rename,
        // refuses to replace a target that appeared during validation.
        guard link(temporaryURL.path, targetPath) == 0 else {
            if errno == EEXIST {
                try secureExistingPath(
                    targetPath,
                    expectedType: mode_t(S_IFREG),
                    permissions: 0o600,
                    expectedOwnerUID: targetOwnerUID
                )
                try validateSQLiteDatabase(at: targetPath)
                return .targetAlreadyExists
            }
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        let directoryDescriptor = open(targetURL.deletingLastPathComponent().path, O_RDONLY)
        guard directoryDescriptor >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { close(directoryDescriptor) }
        guard fsync(directoryDescriptor) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        try secureExistingPath(
            targetPath,
            expectedType: mode_t(S_IFREG),
            permissions: 0o600,
            expectedOwnerUID: targetOwnerUID
        )
        return .restored
    }

    private static func copyRegularFile(
        sourcePath: String,
        destinationPath: String,
        allowedSourceOwnerUIDs: Set<uid_t>,
        targetOwnerUID: uid_t,
        maximumBytes: Int64
    ) throws {
        let sourceDescriptor = open(sourcePath, O_RDONLY | O_NOFOLLOW)
        guard sourceDescriptor >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { close(sourceDescriptor) }

        var sourceInfo = stat()
        guard fstat(sourceDescriptor, &sourceInfo) == 0,
              sourceInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              allowedSourceOwnerUIDs.contains(sourceInfo.st_uid),
              sourceInfo.st_size > 0,
              sourceInfo.st_size <= maximumBytes else {
            throw HelperSecurityStateError.invalidDatabaseBackup("source changed during restore")
        }

        let destinationDescriptor = open(
            destinationPath,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
            mode_t(0o600)
        )
        guard destinationDescriptor >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { close(destinationDescriptor) }
        guard fchmod(destinationDescriptor, mode_t(0o600)) == 0,
              fchown(destinationDescriptor, targetOwnerUID, gid_t.max) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }

        var copied: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            let bytesRead = buffer.withUnsafeMutableBytes {
                read(sourceDescriptor, $0.baseAddress, $0.count)
            }
            guard bytesRead >= 0 else {
                if errno == EINTR { continue }
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }
            if bytesRead == 0 { break }
            copied += Int64(bytesRead)
            guard copied <= maximumBytes else {
                throw HelperSecurityStateError.invalidDatabaseBackup("source exceeds the restore size limit")
            }

            var written = 0
            while written < bytesRead {
                let result = buffer.withUnsafeBytes { rawBuffer -> Int in
                    guard let base = rawBuffer.baseAddress else { return -1 }
                    return write(destinationDescriptor, base.advanced(by: written), bytesRead - written)
                }
                guard result >= 0 else {
                    if errno == EINTR { continue }
                    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
                }
                written += result
            }
        }
        guard copied == sourceInfo.st_size, fsync(destinationDescriptor) == 0 else {
            throw HelperSecurityStateError.invalidDatabaseBackup("source changed or could not be synchronized")
        }
    }

    private static func validateSQLiteDatabase(
        at path: String,
        normalizeStandaloneCopy: Bool = false
    ) throws {
        var database: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX
        guard sqlite3_open_v2(path, &database, flags, nil) == SQLITE_OK, let database else {
            let message = database.map { String(cString: sqlite3_errmsg($0)) } ?? "open failed"
            if database != nil { sqlite3_close(database) }
            throw HelperSecurityStateError.invalidDatabaseBackup("not a readable SQLite database: \(message)")
        }
        defer { sqlite3_close(database) }
        sqlite3_busy_timeout(database, 5_000)

        guard try querySingleText(database, sql: "PRAGMA integrity_check;") == "ok" else {
            throw HelperSecurityStateError.invalidDatabaseBackup("SQLite integrity check failed")
        }

        let requiredColumns: [String: Set<String>] = [
            "rules": ["id", "remote_host", "remote_ip", "remote_port", "direction", "action", "scope", "profile", "enabled"],
            "connections": ["id", "pid", "process_name", "remote_host", "remote_ip", "status", "last_seen"],
            "profiles": ["id", "name", "mode", "is_active"],
            "blocklists": ["id", "name", "url", "enabled"],
            "settings": ["key", "value"],
        ]
        for (table, required) in requiredColumns {
            let columns = try tableColumns(database, table: table)
            guard required.isSubset(of: columns) else {
                throw HelperSecurityStateError.invalidDatabaseBackup("schema is missing required \(table) columns")
            }
        }

        let allowedObjects: Set<String> = Set(requiredColumns.keys).union([
            "idx_rules_profile", "idx_rules_process", "idx_rules_host",
            "idx_conn_status", "idx_conn_pid", "idx_conn_last_seen",
        ])
        var statement: OpaquePointer?
        defer { if statement != nil { sqlite3_finalize(statement) } }
        guard sqlite3_prepare_v2(
            database,
            "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%';",
            -1,
            &statement,
            nil
        ) == SQLITE_OK else {
            throw HelperSecurityStateError.invalidDatabaseBackup(
                "could not inspect SQLite schema: \(String(cString: sqlite3_errmsg(database)))"
            )
        }
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let typePointer = sqlite3_column_text(statement, 0),
                  let namePointer = sqlite3_column_text(statement, 1) else {
                throw HelperSecurityStateError.invalidDatabaseBackup("malformed SQLite schema")
            }
            let type = String(cString: typePointer)
            let name = String(cString: namePointer)
            guard (type == "table" || type == "index"), allowedObjects.contains(name) else {
                throw HelperSecurityStateError.invalidDatabaseBackup("unexpected SQLite schema object")
            }
        }
        if normalizeStandaloneCopy {
            var message: UnsafeMutablePointer<CChar>?
            defer { if message != nil { sqlite3_free(message) } }
            let result = sqlite3_exec(
                database,
                "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;",
                nil,
                nil,
                &message
            )
            guard result == SQLITE_OK else {
                let detail = message.map { String(cString: $0) }
                    ?? String(cString: sqlite3_errmsg(database))
                throw HelperSecurityStateError.invalidDatabaseBackup(
                    "could not normalize standalone SQLite snapshot: \(detail)"
                )
            }
        }
    }

    private static func querySingleText(_ database: OpaquePointer, sql: String) throws -> String? {
        var statement: OpaquePointer?
        defer { if statement != nil { sqlite3_finalize(statement) } }
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK else {
            throw HelperSecurityStateError.invalidDatabaseBackup(
                "SQLite validation query failed: \(String(cString: sqlite3_errmsg(database)))"
            )
        }
        guard sqlite3_step(statement) == SQLITE_ROW,
              let value = sqlite3_column_text(statement, 0) else { return nil }
        return String(cString: value)
    }

    private static func tableColumns(_ database: OpaquePointer, table: String) throws -> Set<String> {
        var statement: OpaquePointer?
        defer { if statement != nil { sqlite3_finalize(statement) } }
        guard sqlite3_prepare_v2(database, "PRAGMA table_info('\(table)');", -1, &statement, nil) == SQLITE_OK else {
            throw HelperSecurityStateError.invalidDatabaseBackup(
                "could not inspect SQLite table: \(String(cString: sqlite3_errmsg(database)))"
            )
        }
        var columns: Set<String> = []
        while sqlite3_step(statement) == SQLITE_ROW {
            if let value = sqlite3_column_text(statement, 1) {
                columns.insert(String(cString: value))
            }
        }
        return columns
    }

    private static func pathExistsIncludingSymlink(_ path: String) throws -> Bool {
        var info = stat()
        if lstat(path, &info) == 0 { return true }
        if errno == ENOENT { return false }
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }

    private static func secureExistingPath(
        _ path: String,
        expectedType: mode_t,
        permissions: mode_t,
        expectedOwnerUID: uid_t
    ) throws {
        var before = stat()
        guard lstat(path, &before) == 0,
              before.st_mode & mode_t(S_IFMT) == expectedType,
              before.st_uid == expectedOwnerUID else {
            throw HelperSecurityStateError.unsafePath(path)
        }
        guard chmod(path, permissions) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }

        var after = stat()
        guard lstat(path, &after) == 0,
              after.st_mode & mode_t(S_IFMT) == expectedType,
              after.st_uid == expectedOwnerUID,
              after.st_mode & 0o777 == permissions else {
            throw HelperSecurityStateError.unsafePath(path)
        }
    }
}

enum HelperAuthorizationPolicy {
    /// An unclaimed helper may only be claimed by the active, non-root console
    /// administrator. Once claimed, only that exact UID is accepted.
    static func allows(
        peerUID: uid_t,
        persistedOwnerUID: uid_t?,
        consoleUID: uid_t?,
        peerIsAdmin: Bool
    ) -> Bool {
        if let persistedOwnerUID {
            return peerUID != 0 && peerUID == persistedOwnerUID && peerIsAdmin
        }
        guard peerUID != 0, let consoleUID else { return false }
        return peerUID == consoleUID && peerIsAdmin
    }

    /// A demoted/deleted persisted owner is treated as unclaimed so the active
    /// console administrator can recover the helper without weakening the
    /// exact-owner rule while the original owner remains an administrator.
    static func allows(
        peerUID: uid_t,
        persistedOwnerUID: uid_t?,
        persistedOwnerIsAdmin: Bool,
        consoleUID: uid_t?,
        peerIsAdmin: Bool
    ) -> Bool {
        allows(
            peerUID: peerUID,
            persistedOwnerUID: persistedOwnerIsAdmin ? persistedOwnerUID : nil,
            consoleUID: consoleUID,
            peerIsAdmin: peerIsAdmin
        )
    }

    static func allows(peerUID: uid_t, consoleUID: uid_t?, peerIsAdmin: Bool) -> Bool {
        allows(
            peerUID: peerUID,
            persistedOwnerUID: nil,
            consoleUID: consoleUID,
            peerIsAdmin: peerIsAdmin
        )
    }

    static func allowsExistingClient(
        peerUID: uid_t,
        ownerUID: uid_t?,
        peerIsAdmin: Bool
    ) -> Bool {
        guard peerUID != 0, let ownerUID else { return false }
        return peerUID == ownerUID && peerIsAdmin
    }
}
