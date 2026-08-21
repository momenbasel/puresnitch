import Foundation

/// Bounded, exactly-once storage for DNS decisions awaiting an XPC client.
/// Callbacks are always invoked after the lock is released.
final class PendingDNSAsks: @unchecked Sendable {
    typealias Completion = (Bool) -> Void

    private let lock = NSLock()
    private let capacity: Int
    private var completions: [UUID: Completion] = [:]

    init(capacity: Int) {
        precondition(capacity > 0, "pending DNS ask capacity must be positive")
        self.capacity = capacity
    }

    func register(_ completion: @escaping Completion) -> UUID? {
        lock.lock()
        defer { lock.unlock() }
        guard completions.count < capacity else { return nil }
        let id = UUID()
        completions[id] = completion
        return id
    }

    @discardableResult
    func settle(id: UUID, allow: Bool) -> Bool {
        lock.lock()
        let completion = completions.removeValue(forKey: id)
        lock.unlock()
        completion?(allow)
        return completion != nil
    }

    @discardableResult
    func drain(allow: Bool) -> Int {
        lock.lock()
        let pending = Array(completions.values)
        completions.removeAll()
        lock.unlock()
        for completion in pending { completion(allow) }
        return pending.count
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return completions.count
    }
}
