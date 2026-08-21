import Foundation
import Darwin

// The helper creates root-owned policy, history, token, and anchor files. Set
// this before any filesystem work so newly-created SQLite sidecars are private.
_ = umask(mode_t(0o077))

PSLog.info(PSLog.helper, "PureSnitchHelper starting v\(AppConstants.version) pid=\(getpid())")

if CommandLine.arguments.dropFirst().first == "--cleanup" {
    guard geteuid() == 0 else {
        PSLog.error(PSLog.helper, "PF cleanup requires root privileges")
        exit(1)
    }
    guard CommandLine.arguments.count == 2 else {
        PSLog.error(PSLog.helper, "PF cleanup does not accept additional arguments")
        exit(1)
    }
    do {
        try HelperSecurityState.prepareSupportDirectory(at: "/Library/Application Support/PureSnitch")
        try PFManager().cleanupOrphanedStateForStandaloneProcess()
        PSLog.info(PSLog.helper, "PureSnitch PF cleanup completed")
        exit(0)
    } catch {
        PSLog.error(PSLog.helper, "PureSnitch PF cleanup failed: \(error.localizedDescription)")
        exit(1)
    }
}

if CommandLine.arguments.dropFirst().first == "--restore-homebrew-database" {
    guard geteuid() == 0 else {
        PSLog.error(PSLog.helper, "database restore requires root privileges")
        exit(1)
    }
    guard CommandLine.arguments.count == 3 else {
        PSLog.error(PSLog.helper, "database restore requires exactly one backup path")
        exit(1)
    }
    let supportDirectory = "/Library/Application Support/PureSnitch"
    let targetPath = (supportDirectory as NSString).appendingPathComponent("puresnitch.sqlite")
    do {
        try HelperSecurityState.prepareSupportDirectory(at: supportDirectory)
        let result = try HelperSecurityState.restoreDatabase(
            sourcePath: CommandLine.arguments[2],
            targetPath: targetPath,
            // Never promote a Homebrew-user-owned file into the root policy
            // store. Future migrations must establish root provenance or use
            // a signed-GUI import that treats the backup as untrusted data.
            allowedSourceOwnerUIDs: [0]
        )
        switch result {
        case .sourceMissing:
            PSLog.info(PSLog.helper, "Homebrew database backup is absent; fresh install continues")
        case .targetAlreadyExists:
            PSLog.info(PSLog.helper, "existing PureSnitch database preserved; restore skipped")
        case .restored:
            PSLog.info(PSLog.helper, "PureSnitch database restored from validated Homebrew backup")
        }
        exit(0)
    } catch {
        PSLog.error(PSLog.helper, "PureSnitch database restore failed: \(error.localizedDescription)")
        exit(1)
    }
}

let listener = NSXPCListener(machServiceName: AppConstants.xpcMachServiceName)

// `service` MUST outlive this scope. NSXPCListener holds its delegate weakly,
// so when the HelperService was created inside a `do { }` block it was
// deallocated the moment the block ended, the delegate went nil, and the
// listener then rejected *every* incoming connection
// ("Peer connection was rejected by the listener"). The app therefore showed
// zero traffic and zero rules even after the user approved the daemon.
let service: HelperService
do {
    service = try HelperService(listener: listener)
} catch {
    PSLog.error(PSLog.helper, "service init failed: \(error)")
    exit(1)
}
service.start()

// launchd sends SIGTERM during replacement/restart. Dispatch signal sources let
// the helper drain DNS cleanly; when enforcement is desired, its validated PF
// subanchor/reference intentionally remains live until the next instance adopts
// and reloads it. Explicit unregister uses prepareForUnregistration instead.
signal(SIGTERM, SIG_IGN)
signal(SIGINT, SIG_IGN)
let signalQueue = DispatchQueue(label: "io.moamenbasel.puresnitch.shutdown")
let terminationSignals = [SIGTERM, SIGINT].map { signalNumber in
    let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: signalQueue)
    source.setEventHandler {
        PSLog.info(PSLog.helper, "received signal \(signalNumber); reconciling shutdown with persisted desired state")
        service.shutdown()
        exit(0)
    }
    source.resume()
    return source
}
_ = terminationSignals // retain both sources for the lifetime of the helper

dispatchMain()
