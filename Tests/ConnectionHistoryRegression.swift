import Foundation
import SQLite3

private let HISTORY_SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

private struct ConnectionHistoryFailure: Error, CustomStringConvertible {
    let description: String
}

private func requireConnectionHistory(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    guard condition() else { throw ConnectionHistoryFailure(description: message) }
}

private func historyObservation(
    localAddress: String = "127.0.0.1",
    remoteAddress: String = "192.0.2.10",
    protocolName: String = "tcp"
) -> SocketObservation {
    let connection = Connection(
        pid: 42,
        processName: "Example",
        processPath: "/Applications/Example.app/Contents/MacOS/Example",
        localPort: 50_000,
        remoteHost: remoteAddress,
        remoteIP: remoteAddress,
        remotePort: 443,
        direction: .outgoing,
        status: .established,
        protocolName: protocolName
    )
    return SocketObservation(
        connection: connection,
        identity: SocketIdentity(
            pid: connection.pid,
            processPath: connection.processPath,
            localAddress: localAddress,
            localPort: connection.localPort,
            remoteAddress: remoteAddress,
            remotePort: connection.remotePort,
            direction: connection.direction,
            protocolName: protocolName
        )
    )
}

private func testActiveConnectionIdentity() throws {
    var tracker = ActiveConnectionTracker()
    let firstTime = Date(timeIntervalSince1970: 1_000)
    let secondTime = Date(timeIntervalSince1970: 1_002)
    let observation = historyObservation()

    let first = tracker.reconcile([observation], seenAt: firstTime)
    let second = tracker.reconcile([historyObservation()], seenAt: secondTime)
    try requireConnectionHistory(first.count == 1 && second.count == 1, "one socket did not produce one row")
    try requireConnectionHistory(first[0].id == second[0].id, "active socket UUID changed between snapshots")
    try requireConnectionHistory(second[0].firstSeen == firstTime, "active socket firstSeen was overwritten")
    try requireConnectionHistory(second[0].lastSeen == secondTime, "active socket lastSeen was not advanced")

    let duplicateSnapshot = tracker.reconcile(
        [historyObservation(), historyObservation()],
        seenAt: Date(timeIntervalSince1970: 1_004)
    )
    try requireConnectionHistory(duplicateSnapshot.count == 1, "duplicate socket rows in one snapshot were not collapsed")

    let distinct = tracker.reconcile(
        [
            historyObservation(localAddress: "127.0.0.1", protocolName: "tcp"),
            historyObservation(localAddress: "192.0.2.20", protocolName: "tcp"),
            historyObservation(localAddress: "127.0.0.1", protocolName: "udp"),
        ],
        seenAt: Date(timeIntervalSince1970: 1_006)
    )
    try requireConnectionHistory(distinct.count == 3, "local address or transport was omitted from socket identity")
    try requireConnectionHistory(Set(distinct.map(\.id)).count == 3, "distinct active sockets shared a UUID")

    _ = tracker.reconcile([], seenAt: Date(timeIntervalSince1970: 1_008))
    let reopened = tracker.reconcile([historyObservation()], seenAt: Date(timeIntervalSince1970: 1_010))
    try requireConnectionHistory(reopened[0].id != first[0].id, "a socket reused after an observation gap kept the old session UUID")
    try requireConnectionHistory(reopened[0].firstSeen == Date(timeIntervalSince1970: 1_010), "reopened socket kept stale firstSeen")
}

private func withHistoryDatabase(_ body: (URL) throws -> Void) throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("puresnitch-connection-history-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    try body(directory.appendingPathComponent("history.sqlite"))
}

private func seedLegacyConnectionRows(at path: String, count: Int, start: Date) throws {
    var database: OpaquePointer?
    guard sqlite3_open(path, &database) == SQLITE_OK, let database else {
        if database != nil { sqlite3_close(database) }
        throw ConnectionHistoryFailure(description: "could not open legacy history fixture")
    }
    defer { sqlite3_close(database) }

    var statement: OpaquePointer?
    let sql = "INSERT INTO connections(id,status,first_seen,last_seen) VALUES(?,?,?,?);"
    guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK else {
        throw ConnectionHistoryFailure(description: "could not prepare legacy history fixture")
    }
    defer { sqlite3_finalize(statement) }

    guard sqlite3_exec(database, "BEGIN IMMEDIATE;", nil, nil, nil) == SQLITE_OK else {
        throw ConnectionHistoryFailure(description: "could not begin legacy history fixture")
    }
    do {
        for offset in 0..<count {
            sqlite3_reset(statement)
            sqlite3_clear_bindings(statement)
            sqlite3_bind_text(statement, 1, UUID().uuidString, -1, HISTORY_SQLITE_TRANSIENT)
            sqlite3_bind_text(statement, 2, Connection.Status.established.rawValue, -1, HISTORY_SQLITE_TRANSIENT)
            let timestamp = start.addingTimeInterval(TimeInterval(offset)).timeIntervalSince1970
            sqlite3_bind_double(statement, 3, timestamp)
            sqlite3_bind_double(statement, 4, timestamp)
            guard sqlite3_step(statement) == SQLITE_DONE else {
                throw ConnectionHistoryFailure(description: "could not insert legacy history fixture")
            }
        }
        guard sqlite3_exec(database, "COMMIT;", nil, nil, nil) == SQLITE_OK else {
            throw ConnectionHistoryFailure(description: "could not commit legacy history fixture")
        }
    } catch {
        sqlite3_exec(database, "ROLLBACK;", nil, nil, nil)
        throw error
    }
}

private func connectionRowCount(at path: String) throws -> Int {
    var database: OpaquePointer?
    guard sqlite3_open_v2(path, &database, SQLITE_OPEN_READONLY, nil) == SQLITE_OK, let database else {
        if database != nil { sqlite3_close(database) }
        throw ConnectionHistoryFailure(description: "could not reopen retained history")
    }
    defer { sqlite3_close(database) }
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(database, "SELECT COUNT(*) FROM connections;", -1, &statement, nil) == SQLITE_OK else {
        throw ConnectionHistoryFailure(description: "could not count retained history")
    }
    defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW else {
        throw ConnectionHistoryFailure(description: "retained history count returned no row")
    }
    return Int(sqlite3_column_int64(statement, 0))
}

private func testConnectionStoreRetention() throws {
    try withHistoryDatabase { databaseURL in
        do { _ = try RuleStore(path: databaseURL.path) }
        let legacyStart = Date(timeIntervalSince1970: 10_000)
        let legacyCount = RuleStore.connectionHistoryLimit + 7
        try seedLegacyConnectionRows(at: databaseURL.path, count: legacyCount, start: legacyStart)

        do {
            let migrated = try RuleStore(path: databaseURL.path)
            let rows = migrated.recentConnections(limit: Int.max)
            try requireConnectionHistory(rows.count == RuleStore.connectionHistoryLimit, "legacy history was not pruned to the cap")
            try requireConnectionHistory(
                rows.first?.lastSeen == legacyStart.addingTimeInterval(TimeInterval(legacyCount - 1)),
                "history migration did not retain the newest row"
            )
            try requireConnectionHistory(
                rows.last?.lastSeen == legacyStart.addingTimeInterval(7),
                "history migration retained the wrong cutoff row"
            )
            try requireConnectionHistory(migrated.recentConnections(limit: -1).isEmpty, "negative history limit escaped the cap")

            let sessionID = UUID()
            let originalFirstSeen = Date(timeIntervalSince1970: 50_000)
            let firstUpdate = Connection(
                id: sessionID,
                pid: 7,
                processName: "Updater",
                processPath: "/usr/bin/updater",
                remoteHost: "198.51.100.8",
                remoteIP: "198.51.100.8",
                remotePort: 443,
                status: .established,
                firstSeen: originalFirstSeen,
                lastSeen: originalFirstSeen
            )
            let laterUpdate = Connection(
                id: sessionID,
                pid: 7,
                processName: "Updater",
                processPath: "/usr/bin/updater",
                remoteHost: "198.51.100.8",
                remoteIP: "198.51.100.8",
                remotePort: 443,
                status: .denied,
                firstSeen: originalFirstSeen.addingTimeInterval(20),
                lastSeen: originalFirstSeen.addingTimeInterval(30)
            )
            try migrated.recordConnections([firstUpdate, laterUpdate])
            let retained = migrated.recentConnections(limit: RuleStore.connectionHistoryLimit)
            let updated = retained.first { $0.id == sessionID }
            try requireConnectionHistory(updated?.firstSeen == originalFirstSeen, "upsert did not preserve earliest firstSeen")
            try requireConnectionHistory(
                updated?.lastSeen == originalFirstSeen.addingTimeInterval(30),
                "upsert did not advance lastSeen"
            )
            try requireConnectionHistory(updated?.status == .denied, "upsert did not update mutable connection fields")
            let denied = migrated.recentConnections(limit: 10, status: .denied)
            try requireConnectionHistory(denied.contains { $0.id == sessionID }, "status-filtered history lost an upserted row")
        }

        let retainedRowCount = try connectionRowCount(at: databaseURL.path)
        try requireConnectionHistory(
            retainedRowCount == RuleStore.connectionHistoryLimit,
            "physical connection row count exceeded the retention cap"
        )
    }
}

func testConnectionHistoryRetention() throws {
    try testActiveConnectionIdentity()
    try testConnectionStoreRetention()
}
