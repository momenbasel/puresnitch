import Foundation

final class BlocklistManager: @unchecked Sendable {
    struct RefreshSummary: Sendable {
        let refreshed: Int
        let failures: [String]
    }

    private struct FetchResult: Sendable {
        let domains: Set<String>?
        let error: String?
    }

    private let store: RuleStore
    private let cacheDirectory: URL
    private var storedDomains: Set<String> = []
    private let queue = DispatchQueue(label: "io.moamenbasel.puresnitch.blocklists")
    var onUpdate: ((Int) -> Void)?

    var domains: Set<String> { queue.sync { storedDomains } }

    init(
        store: RuleStore,
        cacheDirectory: URL = AppConstants.sharedDataDir
            .appendingPathComponent("BlocklistCache", isDirectory: true)
    ) {
        self.store = store
        self.cacheDirectory = cacheDirectory
    }

    @discardableResult
    func refresh() async -> RefreshSummary {
        let lists = store.allBlocklists().filter { $0.enabled }
        var domainsByList: [UUID: Set<String>] = [:]
        for list in lists {
            if let cached = cachedDomains(for: list) {
                domainsByList[list.id] = cached
            }
        }

        var refreshed = 0
        var failures: [String] = []
        await withTaskGroup(of: (BlocklistInfo, FetchResult).self) { group in
            for list in lists {
                group.addTask { (list, await self.fetch(list)) }
            }
            for await (list, result) in group {
                guard let set = result.domains else {
                    failures.append("\(list.name): \(result.error ?? "download failed")")
                    continue
                }

                domainsByList[list.id] = set
                do {
                    try saveCache(set, for: list)
                } catch {
                    failures.append("\(list.name): could not save last-known-good cache (\(error.localizedDescription))")
                }

                var updated = list
                updated.entryCount = set.count
                updated.lastUpdated = Date()
                do {
                    try self.store.updateBlocklist(updated)
                    refreshed += 1
                } catch {
                    failures.append("\(list.name): could not save refresh status (\(error.localizedDescription))")
                }
            }
        }

        let merged = domainsByList.values.reduce(into: Set<String>()) { result, set in
            result.formUnion(set)
        }
        queue.sync { storedDomains = merged }
        onUpdate?(merged.count)
        return RefreshSummary(refreshed: refreshed, failures: failures)
    }

    private func fetch(_ list: BlocklistInfo) async -> FetchResult {
        guard let url = URL(string: list.url) else {
            return FetchResult(domains: nil, error: "invalid URL")
        }
        // Some maintained lists are close to 1 MB and their mirrors can take
        // longer than 15 seconds to begin streaming. Cached data remains active
        // while this bounded refresh runs.
        var req = URLRequest(url: url, timeoutInterval: 45)
        req.setValue("PureSnitch/\(AppConstants.version)", forHTTPHeaderField: "User-Agent")
        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            // Without this check an error page parses into junk "domains":
            // GitHub's 404 body alone yields an entry called "Found".
            guard let http = response as? HTTPURLResponse else {
                return FetchResult(domains: nil, error: "non-HTTP response")
            }
            guard (200...299).contains(http.statusCode) else {
                let message = "HTTP \(http.statusCode)"
                PSLog.error(PSLog.dns, "blocklist \(list.name) returned \(message)")
                return FetchResult(domains: nil, error: message)
            }
            if http.mimeType?.lowercased() == "text/html" {
                return FetchResult(domains: nil, error: "unexpected HTML response")
            }
            guard let text = String(data: data, encoding: .utf8) else {
                return FetchResult(domains: nil, error: "response is not UTF-8")
            }
            let parsed = parse(text)
            guard !parsed.isEmpty else {
                return FetchResult(domains: nil, error: "response contained no domains")
            }
            return FetchResult(domains: parsed, error: nil)
        } catch {
            PSLog.error(PSLog.dns, "blocklist fetch failed: \(list.name) - \(error)")
            return FetchResult(domains: nil, error: error.localizedDescription)
        }
    }

    private func cacheURL(for list: BlocklistInfo) -> URL {
        cacheDirectory
            .appendingPathComponent(list.id.uuidString.lowercased())
            .appendingPathExtension("txt")
    }

    private func cachedDomains(for list: BlocklistInfo) -> Set<String>? {
        guard let text = try? String(contentsOf: cacheURL(for: list), encoding: .utf8) else {
            return nil
        }
        let cached = Set(text.split(separator: "\n").map(String.init))
        return cached.isEmpty ? nil : cached
    }

    private func saveCache(_ domains: Set<String>, for list: BlocklistInfo) throws {
        try FileManager.default.createDirectory(
            at: cacheDirectory,
            withIntermediateDirectories: true,
            attributes: nil
        )
        let text = domains.sorted().joined(separator: "\n") + "\n"
        try text.write(to: cacheURL(for: list), atomically: true, encoding: .utf8)
    }

    private func parse(_ text: String) -> Set<String> {
        var out: Set<String> = []
        out.reserveCapacity(50_000)
        for raw in text.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            // "[Adblock Plus]" heads every Adblock-syntax list.
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("!") || line.hasPrefix("[") { continue }
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            if parts.isEmpty { continue }
            var host = parts.last ?? ""
            if parts.count >= 2, (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1" || parts[0] == "::1") {
                host = parts[1]
            }
            if host.hasPrefix("||") {
                let idx = host.firstIndex(of: "^") ?? host.endIndex
                host = String(host[host.index(host.startIndex, offsetBy: 2)..<idx])
            }
            host = host.lowercased()
            if host.contains("/") { continue }
            if host == "localhost" || host == "0.0.0.0" || host == "broadcasthost" { continue }
            if host.isEmpty { continue }
            out.insert(host)
        }
        return out
    }
}
