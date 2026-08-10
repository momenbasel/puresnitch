import Foundation

PSLog.info(PSLog.helper, "PureSnitchHelper starting v\(AppConstants.version) pid=\(getpid())")

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

dispatchMain()
