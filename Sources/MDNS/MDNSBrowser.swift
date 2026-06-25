/// MDNS Browser (Tier-1 facade)
///
/// Browses for DNS-SD services using mDNS. The public surface is `[UInt8]` /
/// `MDNSService` / `IPAddress`; NIO is used only internally for I/O.

import _Concurrency   // REQUIRED under Embedded for AsyncStream/Task/CancellationError
import DNSWire
import P2PCoreTransport
import P2PCoreCrypto
#if !hasFeature(Embedded)
import Logging
#endif

/// Browses for DNS-SD services using mDNS.
///
/// ## Example
/// ```swift
/// let browser = MDNSBrowser()
/// for try await service in try await browser.browse("_http._tcp.local.") {
///     print("Found: \(service.name)")
/// }
/// ```
public actor MDNSBrowser {

    /// Configuration for the browser.
    public struct Configuration: Sendable {
        /// Query interval for refreshing services.
        public var queryInterval: Duration

        /// Whether to automatically resolve found services.
        public var autoResolve: Bool

        /// Whether to use IPv4.
        public var useIPv4: Bool

        /// Whether to use IPv6.
        public var useIPv6: Bool

        /// Network interface name (nil for all interfaces).
        public var networkInterface: String?

        #if !hasFeature(Embedded)
        /// Logger for debug output. Host-only: `swift-log`'s `Logger` has no
        /// Embedded analogue, so the Embedded facade has no logger.
        public var logger: Logger?
        #endif

        #if !hasFeature(Embedded)
        public init(
            queryInterval: Duration = .seconds(120),
            autoResolve: Bool = true,
            useIPv4: Bool = true,
            useIPv6: Bool = true,
            networkInterface: String? = nil,
            logger: Logger? = nil
        ) {
            self.queryInterval = queryInterval
            self.autoResolve = autoResolve
            self.useIPv4 = useIPv4
            self.useIPv6 = useIPv6
            self.networkInterface = networkInterface
            self.logger = logger
        }
        #else
        public init(
            queryInterval: Duration = .seconds(120),
            autoResolve: Bool = true,
            useIPv4: Bool = true,
            useIPv6: Bool = true,
            networkInterface: String? = nil
        ) {
            self.queryInterval = queryInterval
            self.autoResolve = autoResolve
            self.useIPv4 = useIPv4
            self.useIPv6 = useIPv6
            self.networkInterface = networkInterface
        }
        #endif
    }

    private let configuration: Configuration
    // The transport is held behind the `any` existential on host (so the
    // package-internal injection seam can swap in a test fake) and behind the
    // concrete default type under Embedded (where `any` is unavailable).
    #if !hasFeature(Embedded)
    private let transport: any MDNSTransport
    #else
    private let transport: DefaultMDNSTransport
    #endif
    private let timer: MDNSDefaultTimer

    private var discoveryStream: AsyncStream<Result<MDNSService, MDNSError>>?
    private var discoveryContinuation: AsyncStream<Result<MDNSService, MDNSError>>.Continuation?
    private var services: [String: MDNSService] = [:]
    private var browsingTypes: Set<String> = []
    private var isStarted = false
    private var receiveTask: Task<Void, Never>?
    private var queryTask: Task<Void, Never>?

    #if !hasFeature(Embedded)
    private var logger: MDNSLogger? { configuration.logger }
    #else
    private var logger: MDNSLogger? { nil }
    #endif

    /// Creates a browser with the given configuration.
    ///
    /// - Parameter configuration: Browser configuration.
    public init(configuration: Configuration = .init()) {
        self.configuration = configuration
        self.transport = DefaultMDNSTransport(
            configuration: MDNSTransportConfiguration(
                useIPv4: configuration.useIPv4,
                useIPv6: configuration.useIPv6,
                networkInterface: configuration.networkInterface
            )
        )
        self.timer = MDNSDefaultTimer()
    }

    #if !hasFeature(Embedded)
    /// Creates a browser with a custom transport (package-internal injection seam).
    /// Host-only: the `any` existential parameter is unavailable under Embedded.
    package init(
        configuration: Configuration = .init(),
        transport: any MDNSTransport
    ) {
        self.configuration = configuration
        self.transport = transport
        self.timer = MDNSDefaultTimer()
    }
    #endif

    deinit {
        receiveTask?.cancel()
        queryTask?.cancel()
    }

    /// Starts browsing for a service type and returns the typed discovery stream.
    ///
    /// Calling `browse` more than once adds another service type to the same
    /// discovery stream, which is returned again.
    ///
    /// - Parameter serviceType: The service type (e.g. "_http._tcp.local.").
    /// - Returns: An async sequence of discovered `MDNSService` values.
    @discardableResult
    public func browse(_ serviceType: String) async throws(MDNSError) -> MDNSDiscoveries {
        let discoveries = ensureDiscoveryStream()

        try await ensureStarted()

        browsingTypes.insert(serviceType)
        try await sendQuery(for: serviceType)

        if queryTask == nil {
            // `weak`/`unowned` are forbidden under Embedded; the host build keeps
            // the weak capture (so dropping the browser without `stop()` does not
            // leak via the task→self→task cycle). Under Embedded the spawn is
            // unreachable at runtime (the transport's `start()` throws above before
            // we get here), so the strong capture never forms a live cycle.
            #if !hasFeature(Embedded)
            queryTask = Task { [weak self] in
                await self?.runPeriodicQueries()
            }
            #else
            queryTask = Task { [self] in
                await runPeriodicQueries()
            }
            #endif
        }

        logger?.debug("Started browsing for \(serviceType)")
        return discoveries
    }

    /// Stops the browser and finishes the discovery stream.
    public func stop() async {
        guard isStarted else { return }
        isStarted = false

        receiveTask?.cancel()
        receiveTask = nil

        queryTask?.cancel()
        queryTask = nil

        do {
            try await transport.shutdown()
        } catch {
            logger?.error("MDNSBrowser transport shutdown failed: \(error)")
        }

        discoveryContinuation?.finish()
        discoveryContinuation = nil
        discoveryStream = nil

        browsingTypes.removeAll()
        services.removeAll()

        logger?.info("MDNSBrowser stopped")
    }

    /// All currently known services.
    public var knownServices: [MDNSService] {
        Array(services.values)
    }

    // MARK: - Private

    private func ensureDiscoveryStream() -> MDNSDiscoveries {
        if let discoveryStream {
            return MDNSDiscoveries(base: discoveryStream)
        }
        let (stream, continuation) = AsyncStream.makeStream(of: Result<MDNSService, MDNSError>.self)
        self.discoveryStream = stream
        self.discoveryContinuation = continuation
        return MDNSDiscoveries(base: stream)
    }

    private func ensureStarted() async throws(MDNSError) {
        guard !isStarted else { return }
        isStarted = true

        do {
            try await transport.start()
        } catch {
            isStarted = false
            // The transport seam throws the facade error type directly; rethrow it.
            throw error
        }

        // See the capture-list note in `browse(_:)`: weak on host, strong (and
        // runtime-unreachable) under Embedded where `weak` is forbidden.
        #if !hasFeature(Embedded)
        receiveTask = Task { [weak self] in
            guard let self else { return }
            for await received in self.transport.messages {
                await self.processMessage(received.message)
            }
        }
        #else
        receiveTask = Task { [self] in
            for await received in transport.messages {
                await processMessage(received.message)
            }
        }
        #endif

        logger?.info("MDNSBrowser started")
    }

    private func yield(_ service: MDNSService) {
        discoveryContinuation?.yield(.success(service))
    }

    private func processMessage(_ message: DNSMessage) async {
        guard message.isResponse else { return }
        for answer in message.answers {
            processRecord(answer)
        }
        for additional in message.additional {
            processRecord(additional)
        }
    }

    private func processRecord(_ record: DNSResourceRecord) {
        switch record.rdata {
        case .ptr(let serviceName):
            handlePTRRecord(answer: record, serviceName: serviceName)
        case .srv(let srv):
            handleSRVRecord(answer: record, srv: srv)
        case .txt(let strings):
            handleTXTRecord(answer: record, strings: strings)
        case .a(let address):
            handleARecord(answer: record, address: address)
        case .aaaa(let address):
            handleAAAARecord(answer: record, address: address)
        default:
            break
        }
    }

    private func handlePTRRecord(answer: DNSResourceRecord, serviceName: DNSName) {
        // Goodbye (TTL == 0): remove and re-emit the last-known state.
        if answer.ttl == 0 {
            let fullName = serviceName.description
            if let service = services.removeValue(forKey: fullName) {
                yield(service)
                logger?.debug("Service removed: \(service.name)")
            }
            return
        }

        let serviceType = answer.name.description
        let fullName = serviceName.description

        guard browsingTypes.contains(serviceType) else { return }

        let instanceName = extractInstanceName(from: fullName, type: serviceType)

        if services[fullName] == nil {
            let service = MDNSService(
                name: instanceName,
                type: serviceType.replacingMDNSLocalSuffix(),
                domain: "local",
                ttl: answer.ttl
            )
            services[fullName] = service
            yield(service)
            logger?.debug("Service found: \(instanceName)")

            if configuration.autoResolve {
                // See the capture-list note in `browse(_:)`.
                #if !hasFeature(Embedded)
                Task { [weak self] in
                    guard let self else { return }
                    await self.resolve(fullName: service.fullName)
                }
                #else
                Task { [self] in
                    await resolve(fullName: service.fullName)
                }
                #endif
            }
        }
    }

    private func resolve(fullName: String) async {
        guard isStarted else { return }

        // Build the query (typed codec error) and send it (typed transport error)
        // in separate typed do/catch blocks. Keeping each `catch` bound to one
        // typed error avoids both `any Error` and `catch ... as <Error>` — the
        // latter crashes SILGen in async throwing contexts (project rule).
        let message: DNSMessage
        do {
            let name = try DNSName(fullName)
            message = DNSMessage.mdnsQuery(
                name: name,
                types: [.srv, .txt],
                unicastResponse: true
            )
        } catch {
            discoveryContinuation?.yield(.failure(.codec(error)))
            logger?.debug("Auto-resolve failed for \(fullName): \(error)")
            return
        }

        do {
            try await transport.send(message)
        } catch {
            discoveryContinuation?.yield(.failure(error))
            logger?.debug("Auto-resolve send failed for \(fullName): \(error)")
        }
    }

    private func handleSRVRecord(answer: DNSResourceRecord, srv: SRVRecord) {
        let fullName = answer.name.description
        guard var service = services[fullName] else { return }
        service.host = srv.target.name
        service.port = srv.port
        service.priority = srv.priority
        service.weight = srv.weight
        services[fullName] = service
        yield(service)
        logger?.debug("Service resolved: \(service.name) -> \(srv.target.name):\(srv.port)")
    }

    private func handleTXTRecord(answer: DNSResourceRecord, strings: [String]) {
        let fullName = answer.name.description
        guard var service = services[fullName] else { return }
        service.txt = Self.txtDictionary(from: strings)
        services[fullName] = service
        yield(service)
    }

    private func handleARecord(answer: DNSResourceRecord, address: IPv4Address) {
        let hostName = answer.name.name
        let ip = IPAddress(address)
        for (key, var service) in services {
            if service.host == hostName && !service.addresses.contains(ip) {
                service.addresses.append(ip)
                services[key] = service
                yield(service)
            }
        }
    }

    private func handleAAAARecord(answer: DNSResourceRecord, address: IPv6Address) {
        let hostName = answer.name.name
        let ip = IPAddress(address)
        for (key, var service) in services {
            if service.host == hostName && !service.addresses.contains(ip) {
                service.addresses.append(ip)
                services[key] = service
                yield(service)
            }
        }
    }

    private func extractInstanceName(from fullName: String, type: String) -> String {
        var name = fullName
        if name.hasSuffix(type) {
            name = String(name.dropLast(type.count))
        }
        if name.hasSuffix(".") {
            name = String(name.dropLast())
        }
        return name
    }

    private func sendQuery(for serviceType: String) async throws(MDNSError) {
        // Encode (typed codec error) then send (typed transport error) in
        // separate typed do/catch blocks — no `any Error`, no `as` cast.
        let message: DNSMessage
        do {
            message = try DNSMessage.mdnsQuery(for: serviceType)
        } catch {
            throw MDNSError.codec(error)
        }
        try await transport.send(message)
    }

    private func runPeriodicQueries() async {
        while !Task.isCancelled && isStarted {
            // Wait one query interval via the timer seam (no `Task.sleep`).
            do {
                try await sleep(configuration.queryInterval)
            } catch {
                // Cancelled wait: stop the loop (the guard above also catches it).
                if !Task.isCancelled {
                    logger?.debug("Periodic query timer error: \(error)")
                }
                continue
            }

            for serviceType in browsingTypes {
                do {
                    try await sendQuery(for: serviceType)
                } catch {
                    logger?.debug("Periodic query error: \(error)")
                }
            }
        }
    }

    /// Suspends for `duration` via the injected `AsyncTimer` (no `Task.sleep`).
    private func sleep(_ duration: Duration) async throws(CancellationError) {
        let nanos = duration.facadeNanoseconds
        let deadline = timer.monotonicNanos() &+ nanos
        try await timer.sleep(untilNanos: deadline)
    }

    /// Parses DNS TXT strings ("key=value" / "key") into `[String: [UInt8]]`.
    static func txtDictionary(from strings: [String]) -> [String: [UInt8]] {
        var result: [String: [UInt8]] = [:]
        for string in strings where !string.isEmpty {
            if let equalIndex = string.firstIndex(of: "=") {
                let key = String(string[..<equalIndex])
                let value = String(string[string.index(after: equalIndex)...])
                result[key] = Array(value.utf8)
            } else {
                result[string] = []
            }
        }
        return result
    }
}

private extension String {
    /// Drops a trailing ".local." suffix from a DNS-SD service type.
    func replacingMDNSLocalSuffix() -> String {
        guard hasSuffix(".local.") else { return self }
        return String(dropLast(".local.".count))
    }
}
