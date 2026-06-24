/// MDNS Browser (Tier-1 facade)
///
/// Browses for DNS-SD services using mDNS. The public surface is `[UInt8]` /
/// `MDNSService` / `IPAddress`; NIO is used only internally for I/O.

import DNSWire
import NIOUDPTransport
import P2PCoreTransport
import Logging

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

        /// Logger for debug output.
        public var logger: Logger?

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
    }

    private let configuration: Configuration
    private let transport: any MDNSTransport

    private var discoveryStream: AsyncStream<Result<MDNSService, MDNSError>>?
    private var discoveryContinuation: AsyncStream<Result<MDNSService, MDNSError>>.Continuation?
    private var services: [String: MDNSService] = [:]
    private var browsingTypes: Set<String> = []
    private var isStarted = false
    private var receiveTask: Task<Void, Never>?
    private var queryTask: Task<Void, Never>?

    private var logger: Logger? { configuration.logger }

    /// Creates a browser with the given configuration.
    ///
    /// - Parameter configuration: Browser configuration.
    public init(configuration: Configuration = .init()) {
        self.configuration = configuration
        self.transport = NIODNSTransport(
            configuration: MDNSTransportConfiguration(
                useIPv4: configuration.useIPv4,
                useIPv6: configuration.useIPv6,
                networkInterface: configuration.networkInterface
            )
        )
    }

    /// Creates a browser with a custom transport (package-internal injection seam).
    package init(
        configuration: Configuration = .init(),
        transport: any MDNSTransport
    ) {
        self.configuration = configuration
        self.transport = transport
    }

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
            queryTask = Task { [weak self] in
                await self?.runPeriodicQueries()
            }
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
            throw MDNSError.mapping(error, context: "Browser transport start failed")
        }

        receiveTask = Task { [weak self] in
            guard let self else { return }
            for await received in self.transport.messages {
                await self.processMessage(received.message)
            }
        }

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
                Task { [weak self] in
                    guard let self else { return }
                    await self.resolve(fullName: service.fullName)
                }
            }
        }
    }

    private func resolve(fullName: String) async {
        guard isStarted else { return }
        do {
            let name = try DNSName(fullName)
            let message = DNSMessage.mdnsQuery(
                name: name,
                types: [.srv, .txt],
                unicastResponse: true
            )
            try await transport.send(message)
        } catch let error as DNSError {
            discoveryContinuation?.yield(.failure(.codec(error)))
            logger?.debug("Auto-resolve failed for \(fullName): \(error)")
        } catch {
            discoveryContinuation?.yield(
                .failure(.networkError("Auto-resolve failed for \(fullName): \(error)"))
            )
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
        do {
            let message = try DNSMessage.mdnsQuery(for: serviceType)
            try await transport.send(message)
        } catch {
            throw MDNSError.mapping(error, context: "Failed to send query for \(serviceType)")
        }
    }

    private func runPeriodicQueries() async {
        while !Task.isCancelled && isStarted {
            do {
                try await Task.sleep(for: configuration.queryInterval)
                for serviceType in browsingTypes {
                    try await sendQuery(for: serviceType)
                }
            } catch {
                if !Task.isCancelled {
                    logger?.debug("Periodic query error: \(error)")
                }
            }
        }
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
