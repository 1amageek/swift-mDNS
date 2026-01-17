/// Service Browser
///
/// High-level API for browsing DNS-SD services using mDNS.

import Foundation
import NIOCore
import NIOUDPTransport
import Logging

/// Events emitted by the service browser.
public enum ServiceBrowserEvent: Sendable {
    /// A new service was discovered.
    case found(Service)

    /// A service was updated (e.g., new addresses resolved).
    case updated(Service)

    /// A service was removed (goodbye packet or TTL expired).
    case removed(Service)

    /// An error occurred.
    case error(DNSError)
}

/// Browses for DNS-SD services using mDNS.
///
/// ## Example
/// ```swift
/// let browser = ServiceBrowser()
/// try await browser.start()
///
/// // Browse for HTTP services
/// try await browser.browse(for: "_http._tcp.local.")
///
/// for await event in browser.events {
///     switch event {
///     case .found(let service):
///         print("Found: \(service.name)")
///     case .removed(let service):
///         print("Removed: \(service.name)")
///     default:
///         break
///     }
/// }
/// ```
public actor ServiceBrowser {

    /// Configuration for the service browser.
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

        public static let `default` = Configuration()
    }

    private let configuration: Configuration
    private let transport: any MDNSTransport

    private var eventContinuation: AsyncStream<ServiceBrowserEvent>.Continuation?
    private var services: [String: Service] = [:]
    private var browsingTypes: Set<String> = []
    private var isStarted = false
    private var receiveTask: Task<Void, Never>?
    private var queryTask: Task<Void, Never>?

    private var logger: Logger? { configuration.logger }

    /// Creates a service browser with the given configuration.
    ///
    /// - Parameters:
    ///   - configuration: Browser configuration
    ///   - transport: Optional custom transport (uses NIODNSTransport if nil)
    public init(
        configuration: Configuration = .default,
        transport: (any MDNSTransport)? = nil
    ) {
        self.configuration = configuration
        self.transport = transport ?? NIODNSTransport(
            configuration: MDNSTransportConfiguration(
                useIPv4: configuration.useIPv4,
                useIPv6: configuration.useIPv6,
                networkInterface: configuration.networkInterface
            )
        )
    }

    deinit {
        receiveTask?.cancel()
        queryTask?.cancel()
    }

    /// Stream of service browser events.
    public var events: AsyncStream<ServiceBrowserEvent> {
        AsyncStream { continuation in
            self.eventContinuation = continuation

            continuation.onTermination = { @Sendable _ in
                Task { await self.stop() }
            }
        }
    }

    /// Starts the service browser.
    public func start() async throws {
        guard !isStarted else { return }
        isStarted = true

        try await transport.start()

        // Start receiving messages
        receiveTask = Task { [weak self] in
            guard let self = self else { return }
            for await received in self.transport.messages {
                await self.processMessage(received.message)
            }
        }

        logger?.info("ServiceBrowser started")
    }

    /// Stops the service browser.
    public func stop() async {
        guard isStarted else { return }
        isStarted = false

        receiveTask?.cancel()
        receiveTask = nil

        queryTask?.cancel()
        queryTask = nil

        await transport.stop()

        eventContinuation?.finish()
        eventContinuation = nil

        browsingTypes.removeAll()
        services.removeAll()

        logger?.info("ServiceBrowser stopped")
    }

    /// Starts browsing for a service type.
    ///
    /// - Parameter serviceType: The service type to browse for (e.g., "_http._tcp.local.")
    public func browse(for serviceType: String) async throws {
        guard isStarted else {
            throw DNSError.networkError("Browser not started")
        }

        browsingTypes.insert(serviceType)

        // Send initial query
        try await sendQuery(for: serviceType)

        // Start periodic queries if not already running
        if queryTask == nil {
            queryTask = Task { [weak self] in
                await self?.runPeriodicQueries()
            }
        }

        logger?.debug("Started browsing for \(serviceType)")
    }

    /// Stops browsing for a service type.
    public func stopBrowsing(for serviceType: String) {
        browsingTypes.remove(serviceType)

        // Remove services of this type
        let toRemove = services.filter { $0.value.fullType == serviceType }
        for (key, service) in toRemove {
            services.removeValue(forKey: key)
            eventContinuation?.yield(.removed(service))
        }

        logger?.debug("Stopped browsing for \(serviceType)")
    }

    /// Resolves a service to get its host, port, and addresses.
    public func resolve(_ service: Service) async throws -> Service {
        guard isStarted else {
            throw DNSError.networkError("Browser not started")
        }

        // Query for SRV and TXT records
        let name = try DNSName(service.fullName)
        let message = DNSMessage.mdnsQuery(
            name: name,
            types: [.srv, .txt],
            unicastResponse: true
        )

        try await transport.send(message)

        // The response will be handled by the receive loop
        // Return the current service state
        return services[service.fullName] ?? service
    }

    /// Returns all currently known services.
    public var knownServices: [Service] {
        Array(services.values)
    }

    // MARK: - Private

    private func processMessage(_ message: DNSMessage) async {
        // Only process responses
        guard message.isResponse else { return }

        // Process PTR records (service discovery)
        for answer in message.answers {
            switch answer.rdata {
            case .ptr(let serviceName):
                await handlePTRRecord(answer: answer, serviceName: serviceName)

            case .srv(let srv):
                await handleSRVRecord(answer: answer, srv: srv)

            case .txt(let strings):
                await handleTXTRecord(answer: answer, strings: strings)

            case .a(let address):
                await handleARecord(answer: answer, address: address)

            case .aaaa(let address):
                await handleAAAARecord(answer: answer, address: address)

            default:
                break
            }
        }

        // Also process additional records
        for additional in message.additional {
            switch additional.rdata {
            case .a(let address):
                await handleARecord(answer: additional, address: address)

            case .aaaa(let address):
                await handleAAAARecord(answer: additional, address: address)

            case .srv(let srv):
                await handleSRVRecord(answer: additional, srv: srv)

            case .txt(let strings):
                await handleTXTRecord(answer: additional, strings: strings)

            default:
                break
            }
        }
    }

    private func handlePTRRecord(answer: DNSResourceRecord, serviceName: DNSName) async {
        // Check if this is a goodbye (TTL=0)
        if answer.ttl == 0 {
            let fullName = serviceName.description
            if let service = services.removeValue(forKey: fullName) {
                eventContinuation?.yield(.removed(service))
                logger?.debug("Service removed: \(service.name)")
            }
            return
        }

        // Parse service name: "Instance Name._type._protocol.local."
        let serviceType = answer.name.description
        let fullName = serviceName.description

        guard browsingTypes.contains(serviceType) else { return }

        // Extract instance name from full name
        let instanceName = extractInstanceName(from: fullName, type: serviceType)

        if services[fullName] == nil {
            let service = Service(
                name: instanceName,
                type: serviceType.replacingOccurrences(of: ".local.", with: ""),
                domain: "local",
                ttl: answer.ttl,
                lastSeen: Date()
            )
            services[fullName] = service
            eventContinuation?.yield(.found(service))
            logger?.debug("Service found: \(instanceName)")

            // Auto-resolve if enabled
            if configuration.autoResolve {
                Task { [weak self] in
                    try? await self?.resolve(service)
                }
            }
        }
    }

    private func handleSRVRecord(answer: DNSResourceRecord, srv: SRVRecord) async {
        let fullName = answer.name.description

        if var service = services[fullName] {
            service.hostName = srv.target.name
            service.port = srv.port
            service.priority = srv.priority
            service.weight = srv.weight
            service.lastSeen = Date()
            services[fullName] = service
            eventContinuation?.yield(.updated(service))
            logger?.debug("Service resolved: \(service.name) -> \(srv.target.name):\(srv.port)")
        }
    }

    private func handleTXTRecord(answer: DNSResourceRecord, strings: [String]) async {
        let fullName = answer.name.description

        if var service = services[fullName] {
            service.txtRecord = TXTRecord(strings: strings)
            service.lastSeen = Date()
            services[fullName] = service
            eventContinuation?.yield(.updated(service))
        }
    }

    private func handleARecord(answer: DNSResourceRecord, address: IPv4Address) async {
        let hostName = answer.name.name

        // Find services with this hostname
        for (key, var service) in services {
            if service.hostName == hostName && !service.ipv4Addresses.contains(address) {
                service.ipv4Addresses.append(address)
                service.lastSeen = Date()
                services[key] = service
                eventContinuation?.yield(.updated(service))
            }
        }
    }

    private func handleAAAARecord(answer: DNSResourceRecord, address: IPv6Address) async {
        let hostName = answer.name.name

        // Find services with this hostname
        for (key, var service) in services {
            if service.hostName == hostName && !service.ipv6Addresses.contains(address) {
                service.ipv6Addresses.append(address)
                service.lastSeen = Date()
                services[key] = service
                eventContinuation?.yield(.updated(service))
            }
        }
    }

    private func extractInstanceName(from fullName: String, type: String) -> String {
        // fullName: "My Service._http._tcp.local."
        // type: "_http._tcp.local."
        // result: "My Service"
        var name = fullName
        if name.hasSuffix(type) {
            name = String(name.dropLast(type.count))
        }
        if name.hasSuffix(".") {
            name = String(name.dropLast())
        }
        return name
    }

    private func sendQuery(for serviceType: String) async throws {
        let message = try DNSMessage.mdnsQuery(for: serviceType)
        try await transport.send(message)
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
}
