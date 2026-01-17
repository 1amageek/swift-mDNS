/// Service Advertiser
///
/// High-level API for advertising DNS-SD services using mDNS.

import Foundation
import NIOCore
import NIOUDPTransport
import Logging

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Events emitted by the service advertiser.
public enum ServiceAdvertiserEvent: Sendable {
    /// A service was successfully registered.
    case registered(Service)

    /// A service was updated.
    case updated(Service)

    /// A service was unregistered.
    case unregistered(Service)

    /// A name conflict was detected.
    case conflict(originalName: String, newName: String)

    /// An error occurred.
    case error(DNSError)
}

/// Advertises DNS-SD services using mDNS.
///
/// ## Example
/// ```swift
/// let advertiser = ServiceAdvertiser()
/// try await advertiser.start()
///
/// let service = Service(
///     name: "My Web Server",
///     type: "_http._tcp",
///     port: 8080,
///     txtRecord: TXTRecord(["path": "/api"])
/// )
///
/// try await advertiser.register(service)
///
/// // Later...
/// try await advertiser.unregister(service)
/// ```
public actor ServiceAdvertiser {

    /// Configuration for the service advertiser.
    public struct Configuration: Sendable {
        /// Default TTL for records.
        public var ttl: UInt32

        /// Whether to use IPv4.
        public var useIPv4: Bool

        /// Whether to use IPv6.
        public var useIPv6: Bool

        /// Network interface name (nil for all interfaces).
        public var networkInterface: String?

        /// Announcement interval for periodic refresh.
        public var announcementInterval: Duration

        /// Number of announcement retries.
        public var announcementCount: Int

        /// Logger for debug output.
        public var logger: Logger?

        public init(
            ttl: UInt32 = mdnsDefaultTTL,
            useIPv4: Bool = true,
            useIPv6: Bool = true,
            networkInterface: String? = nil,
            announcementInterval: Duration = .seconds(20),
            announcementCount: Int = 3,
            logger: Logger? = nil
        ) {
            self.ttl = ttl
            self.useIPv4 = useIPv4
            self.useIPv6 = useIPv6
            self.networkInterface = networkInterface
            self.announcementInterval = announcementInterval
            self.announcementCount = announcementCount
            self.logger = logger
        }

        public static let `default` = Configuration()
    }

    private let configuration: Configuration
    private let transport: any MDNSTransport

    private var eventContinuation: AsyncStream<ServiceAdvertiserEvent>.Continuation?
    private var registeredServices: [String: Service] = [:]
    private var hostAddresses: [IPv4Address] = []
    private var hostAddresses6: [IPv6Address] = []
    private var hostName: String = ""
    private var isStarted = false
    private var receiveTask: Task<Void, Never>?
    private var refreshTask: Task<Void, Never>?

    private var logger: Logger? { configuration.logger }

    /// Creates a service advertiser with the given configuration.
    ///
    /// - Parameters:
    ///   - configuration: Advertiser configuration
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
        refreshTask?.cancel()
    }

    /// Stream of service advertiser events.
    public var events: AsyncStream<ServiceAdvertiserEvent> {
        AsyncStream { continuation in
            self.eventContinuation = continuation

            continuation.onTermination = { @Sendable _ in
                Task { await self.stop() }
            }
        }
    }

    /// Starts the service advertiser.
    public func start() async throws {
        guard !isStarted else { return }
        isStarted = true

        // Get local host name and addresses
        hostName = ProcessInfo.processInfo.hostName
        await resolveLocalAddresses()

        // Start transport
        try await transport.start()

        // Start receiving messages
        receiveTask = Task { [weak self] in
            guard let self = self else { return }
            for await received in self.transport.messages {
                await self.processQuery(received.message)
            }
        }

        logger?.info("ServiceAdvertiser started")
    }

    /// Stops the service advertiser.
    public func stop() async {
        guard isStarted else { return }
        isStarted = false

        // Send goodbye for all registered services
        for service in registeredServices.values {
            await sendGoodbye(for: service)
        }

        receiveTask?.cancel()
        receiveTask = nil

        refreshTask?.cancel()
        refreshTask = nil

        await transport.stop()

        eventContinuation?.finish()
        eventContinuation = nil

        registeredServices.removeAll()

        logger?.info("ServiceAdvertiser stopped")
    }

    /// Registers a service for advertising.
    ///
    /// - Parameter service: The service to register
    public func register(_ service: Service) async throws {
        guard isStarted else {
            throw DNSError.networkError("Advertiser not started")
        }

        var serviceToRegister = service

        // Ensure port is set
        guard serviceToRegister.port != nil else {
            throw DNSError.invalidName("Service must have a port")
        }

        // Set hostname if not provided
        if serviceToRegister.hostName == nil {
            serviceToRegister.hostName = "\(hostName).local"
        }

        // Set addresses if not provided
        if serviceToRegister.ipv4Addresses.isEmpty {
            serviceToRegister.ipv4Addresses = hostAddresses
        }
        if serviceToRegister.ipv6Addresses.isEmpty {
            serviceToRegister.ipv6Addresses = hostAddresses6
        }

        registeredServices[serviceToRegister.fullName] = serviceToRegister

        // Send announcements
        try await announce(service: serviceToRegister)

        eventContinuation?.yield(.registered(serviceToRegister))
        logger?.info("Service registered: \(serviceToRegister.name)")

        // Start refresh task if not running
        if refreshTask == nil {
            refreshTask = Task { [weak self] in
                await self?.runPeriodicRefresh()
            }
        }
    }

    /// Unregisters a service.
    ///
    /// - Parameter service: The service to unregister
    public func unregister(_ service: Service) async throws {
        guard isStarted else {
            throw DNSError.networkError("Advertiser not started")
        }

        guard let registered = registeredServices.removeValue(forKey: service.fullName) else {
            return
        }

        await sendGoodbye(for: registered)

        eventContinuation?.yield(.unregistered(registered))
        logger?.info("Service unregistered: \(registered.name)")
    }

    /// Updates a registered service.
    ///
    /// - Parameter service: The updated service
    public func update(_ service: Service) async throws {
        guard isStarted else {
            throw DNSError.networkError("Advertiser not started")
        }

        guard registeredServices[service.fullName] != nil else {
            throw DNSError.serviceNotFound(service.name)
        }

        registeredServices[service.fullName] = service

        // Re-announce the updated service
        try await announce(service: service)

        eventContinuation?.yield(.updated(service))
        logger?.info("Service updated: \(service.name)")
    }

    /// Returns all registered services.
    public var services: [Service] {
        Array(registeredServices.values)
    }

    // MARK: - Private

    private func resolveLocalAddresses() async {
        // Get local network interfaces (POSIX - works on macOS and Linux)
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else { return }

        defer { freeifaddrs(ifaddr) }

        var ipv4: [IPv4Address] = []
        var ipv6: [IPv6Address] = []

        var ptr = firstAddr
        while true {
            let interface = ptr.pointee
            let family = interface.ifa_addr.pointee.sa_family

            if family == UInt8(AF_INET) {
                // IPv4
                let addr = interface.ifa_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                let bytes = withUnsafeBytes(of: addr) { Data($0) }
                ipv4.append(IPv4Address(bytes))
            } else if family == UInt8(AF_INET6) {
                // IPv6
                let addr = interface.ifa_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                let bytes = withUnsafeBytes(of: addr) { Data($0) }
                ipv6.append(IPv6Address(bytes))
            }

            guard let next = interface.ifa_next else { break }
            ptr = next
        }

        self.hostAddresses = ipv4
        self.hostAddresses6 = ipv6
    }

    private func processQuery(_ message: DNSMessage) async {
        // Only process queries
        guard !message.isResponse else { return }

        var answers: [DNSResourceRecord] = []
        var additional: [DNSResourceRecord] = []

        for question in message.questions {
            let questionName = question.name.description

            // Check PTR queries for service types
            if question.type == .ptr || question.type == .any {
                for service in registeredServices.values {
                    if questionName == service.fullType {
                        // Add PTR record pointing to the service instance
                        let ptrRecord = makePTRRecord(for: service)
                        answers.append(ptrRecord)

                        // Add SRV, TXT, and address records as additional
                        additional.append(contentsOf: makeServiceRecords(for: service))
                    }
                }
            }

            // Check SRV/TXT queries for specific service instances
            if question.type == .srv || question.type == .txt || question.type == .any {
                if let service = registeredServices[questionName] {
                    additional.append(contentsOf: makeServiceRecords(for: service))
                }
            }

            // Check A/AAAA queries for hostname
            if question.type == .a || question.type == .aaaa || question.type == .any {
                for service in registeredServices.values {
                    if let hostName = service.hostName, question.name.name == hostName {
                        additional.append(contentsOf: makeAddressRecords(for: service))
                    }
                }
            }
        }

        // Send response if we have answers
        if !answers.isEmpty || !additional.isEmpty {
            let response = DNSMessage.response(
                id: 0,
                answers: answers,
                additional: additional,
                isAuthoritative: true
            )

            do {
                try await transport.send(response)
            } catch {
                logger?.debug("Failed to send response: \(error)")
            }
        }
    }

    private func announce(service: Service) async throws {
        let records = makeAllRecords(for: service)

        let response = DNSMessage.response(
            id: 0,
            answers: records,
            isAuthoritative: true
        )

        // Send multiple announcements with exponential backoff
        for i in 0..<configuration.announcementCount {
            try await transport.send(response)

            if i < configuration.announcementCount - 1 {
                // Wait between announcements (1s, 2s, 4s...)
                let delay = Duration.seconds(1 << i)
                try await Task.sleep(for: delay)
            }
        }
    }

    private func sendGoodbye(for service: Service) async {
        let records = makeAllRecords(for: service)
        let goodbyeMessage = DNSMessage.mdnsGoodbye(records: records)

        do {
            try await transport.send(goodbyeMessage)
        } catch {
            logger?.debug("Failed to send goodbye: \(error)")
        }
    }

    private func makeAllRecords(for service: Service) -> [DNSResourceRecord] {
        var records: [DNSResourceRecord] = []
        records.append(makePTRRecord(for: service))
        records.append(contentsOf: makeServiceRecords(for: service))
        records.append(contentsOf: makeAddressRecords(for: service))
        return records
    }

    private func makePTRRecord(for service: Service) -> DNSResourceRecord {
        let typeName = try! DNSName(service.fullType)
        let instanceName = try! DNSName(service.fullName)

        return DNSResourceRecord(
            name: typeName,
            type: .ptr,
            ttl: configuration.ttl,
            rdata: .ptr(instanceName)
        )
    }

    private func makeServiceRecords(for service: Service) -> [DNSResourceRecord] {
        var records: [DNSResourceRecord] = []

        let instanceName = try! DNSName(service.fullName)

        // SRV record
        if let hostName = service.hostName, let port = service.port {
            let target = try! DNSName(hostName)
            let srvData = SRVRecord(
                priority: service.priority,
                weight: service.weight,
                port: port,
                target: target
            )
            records.append(DNSResourceRecord(
                name: instanceName,
                type: .srv,
                cacheFlush: true,
                ttl: configuration.ttl,
                rdata: .srv(srvData)
            ))
        }

        // TXT record
        records.append(DNSResourceRecord(
            name: instanceName,
            type: .txt,
            cacheFlush: true,
            ttl: configuration.ttl,
            rdata: .txt(service.txtRecord.toStrings())
        ))

        return records
    }

    private func makeAddressRecords(for service: Service) -> [DNSResourceRecord] {
        var records: [DNSResourceRecord] = []

        guard let hostName = service.hostName else { return records }
        let name = try! DNSName(hostName)

        // A records
        for addr in service.ipv4Addresses {
            records.append(DNSResourceRecord(
                name: name,
                type: .a,
                cacheFlush: true,
                ttl: configuration.ttl,
                rdata: .a(addr)
            ))
        }

        // AAAA records
        for addr in service.ipv6Addresses {
            records.append(DNSResourceRecord(
                name: name,
                type: .aaaa,
                cacheFlush: true,
                ttl: configuration.ttl,
                rdata: .aaaa(addr)
            ))
        }

        return records
    }

    private func runPeriodicRefresh() async {
        while !Task.isCancelled && isStarted {
            do {
                try await Task.sleep(for: configuration.announcementInterval)

                // Re-announce all services
                for service in registeredServices.values {
                    try await announce(service: service)
                }
            } catch {
                if !Task.isCancelled {
                    logger?.debug("Periodic refresh error: \(error)")
                }
            }
        }
    }
}
