/// MDNS Responder (Tier-1 facade)
///
/// Advertises DNS-SD services using mDNS. The public surface is `MDNSService` /
/// `IPAddress`; NIO is used only internally for I/O.

import DNSWire
import NIOUDPTransport
import P2PCoreTransport
import Logging

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Advertises DNS-SD services using mDNS.
///
/// ## Example
/// ```swift
/// let responder = MDNSResponder()
/// let service = MDNSService(name: "My Web Server", type: "_http._tcp", port: 8080)
/// try await responder.advertise(service)
/// ```
public actor MDNSResponder {

    /// Configuration for the responder.
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
    }

    private let configuration: Configuration
    private let transport: any MDNSTransport

    private var registeredServices: [String: MDNSService] = [:]
    private var hostAddresses: [IPAddress] = []
    private var hostName: String = ""
    private var isStarted = false
    private var receiveTask: Task<Void, Never>?
    private var refreshTask: Task<Void, Never>?

    private var logger: Logger? { configuration.logger }

    /// Creates a responder with the given configuration.
    ///
    /// - Parameter configuration: Responder configuration.
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

    /// Creates a responder with a custom transport (package-internal injection seam).
    package init(
        configuration: Configuration = .init(),
        transport: any MDNSTransport
    ) {
        self.configuration = configuration
        self.transport = transport
    }

    deinit {
        receiveTask?.cancel()
        refreshTask?.cancel()
    }

    /// Advertises a service, starting the responder if needed.
    ///
    /// - Parameter service: The service to advertise (must have a port).
    public func advertise(_ service: MDNSService) async throws(MDNSError) {
        try await ensureStarted()

        var serviceToRegister = service

        guard serviceToRegister.port != nil else {
            throw MDNSError.invalidService("Service must have a port")
        }

        if serviceToRegister.host == nil {
            serviceToRegister.host = "\(hostName).local"
        }

        if serviceToRegister.addresses.isEmpty {
            serviceToRegister.addresses = hostAddresses
        }

        // Validate that all records can be built before registering.
        do {
            _ = try makeAllRecords(for: serviceToRegister)
        } catch {
            throw MDNSError.mapping(error, context: "Failed to build service records")
        }

        registeredServices[serviceToRegister.fullName] = serviceToRegister

        try await announce(service: serviceToRegister)

        logger?.info("Service advertised: \(serviceToRegister.name)")

        if refreshTask == nil {
            refreshTask = Task { [weak self] in
                await self?.runPeriodicRefresh()
            }
        }
    }

    /// Withdraws a previously advertised service (sends a goodbye, TTL == 0).
    ///
    /// - Parameter service: The service to withdraw.
    public func withdraw(_ service: MDNSService) async throws(MDNSError) {
        guard isStarted else {
            throw MDNSError.notStarted
        }

        guard let registered = registeredServices.removeValue(forKey: service.fullName) else {
            throw MDNSError.serviceNotFound(service.name)
        }

        await sendGoodbye(for: registered)
        logger?.info("Service withdrawn: \(registered.name)")
    }

    /// Stops the responder, sending a goodbye for every advertised service.
    public func stop() async {
        guard isStarted else { return }
        isStarted = false

        for service in registeredServices.values {
            await sendGoodbye(for: service)
        }

        receiveTask?.cancel()
        receiveTask = nil

        refreshTask?.cancel()
        refreshTask = nil

        do {
            try await transport.shutdown()
        } catch {
            logger?.error("MDNSResponder transport shutdown failed: \(error)")
        }

        registeredServices.removeAll()
        logger?.info("MDNSResponder stopped")
    }

    /// All advertised services.
    public var services: [MDNSService] {
        Array(registeredServices.values)
    }

    // MARK: - Private

    private func ensureStarted() async throws(MDNSError) {
        guard !isStarted else { return }
        isStarted = true

        hostName = currentHostName()
        resolveLocalAddresses()

        do {
            try await transport.start()
        } catch {
            isStarted = false
            throw MDNSError.mapping(error, context: "Responder transport start failed")
        }

        receiveTask = Task { [weak self] in
            guard let self else { return }
            for await received in self.transport.messages {
                await self.processQuery(received.message)
            }
        }

        logger?.info("MDNSResponder started")
    }

    private func currentHostName() -> String {
        var buffer = [UInt8](repeating: 0, count: 256)
        let result = buffer.withUnsafeMutableBytes { raw -> Int32 in
            raw.baseAddress!.withMemoryRebound(to: CChar.self, capacity: raw.count) {
                gethostname($0, raw.count)
            }
        }
        guard result == 0 else { return "localhost" }
        let nameBytes = Array(buffer.prefix { $0 != 0 })
        return String(decoding: nameBytes, as: UTF8.self)
    }

    private func resolveLocalAddresses() {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else { return }
        defer { freeifaddrs(ifaddr) }

        var addresses: [IPAddress] = []

        var ptr = firstAddr
        while true {
            let interface = ptr.pointee
            let family = interface.ifa_addr.pointee.sa_family

            if family == UInt8(AF_INET) {
                let addr = interface.ifa_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                let octets = withUnsafeBytes(of: addr) { Array($0) }
                if octets.count >= 4 {
                    addresses.append(.v4(octets[0], octets[1], octets[2], octets[3]))
                }
            } else if family == UInt8(AF_INET6) {
                let addr = interface.ifa_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                let octets = withUnsafeBytes(of: addr) { Array($0) }
                if octets.count >= 16 {
                    addresses.append(.v6(InlineIPv6(
                        octets[0], octets[1], octets[2], octets[3],
                        octets[4], octets[5], octets[6], octets[7],
                        octets[8], octets[9], octets[10], octets[11],
                        octets[12], octets[13], octets[14], octets[15]
                    )))
                }
            }

            guard let next = interface.ifa_next else { break }
            ptr = next
        }

        self.hostAddresses = addresses
    }

    private func processQuery(_ message: DNSMessage) async {
        guard !message.isResponse else { return }

        var answers: [DNSResourceRecord] = []
        var additional: [DNSResourceRecord] = []

        for question in message.questions {
            let questionName = question.name.description

            if question.type == .ptr || question.type == .any {
                for service in registeredServices.values where questionName == service.fullType {
                    do {
                        answers.append(try makePTRRecord(for: service))
                        additional.append(contentsOf: try makeServiceRecords(for: service))
                    } catch {
                        logger?.debug("Failed to build PTR response records: \(error)")
                    }
                }
            }

            if question.type == .srv || question.type == .txt || question.type == .any {
                if let service = registeredServices[questionName] {
                    do {
                        additional.append(contentsOf: try makeServiceRecords(for: service))
                    } catch {
                        logger?.debug("Failed to build SRV/TXT response records: \(error)")
                    }
                }
            }

            if question.type == .a || question.type == .aaaa || question.type == .any {
                for service in registeredServices.values {
                    if let host = service.host, question.name.name == host {
                        do {
                            additional.append(contentsOf: try makeAddressRecords(for: service))
                        } catch {
                            logger?.debug("Failed to build address response records: \(error)")
                        }
                    }
                }
            }
        }

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

    private func announce(service: MDNSService) async throws(MDNSError) {
        let records: [DNSResourceRecord]
        do {
            records = try makeAllRecords(for: service)
        } catch {
            throw MDNSError.mapping(error, context: "Failed to build announcement")
        }

        let response = DNSMessage.response(id: 0, answers: records, isAuthoritative: true)

        for i in 0..<configuration.announcementCount {
            do {
                try await transport.send(response)
            } catch {
                throw MDNSError.mapping(error, context: "Failed to send announcement")
            }

            if i < configuration.announcementCount - 1 {
                let delay = Duration.seconds(1 << i)
                do {
                    try await Task.sleep(for: delay)
                } catch {
                    // Task cancelled mid-announcement: stop announcing, not an error.
                    return
                }
            }
        }
    }

    private func sendGoodbye(for service: MDNSService) async {
        do {
            let records = try makeAllRecords(for: service)
            let goodbyeMessage = DNSMessage.mdnsGoodbye(records: records)
            try await transport.send(goodbyeMessage)
        } catch {
            logger?.debug("Failed to send goodbye: \(error)")
        }
    }

    private func makeAllRecords(for service: MDNSService) throws(DNSError) -> [DNSResourceRecord] {
        var records: [DNSResourceRecord] = []
        records.append(try makePTRRecord(for: service))
        records.append(contentsOf: try makeServiceRecords(for: service))
        records.append(contentsOf: try makeAddressRecords(for: service))
        return records
    }

    private func makePTRRecord(for service: MDNSService) throws(DNSError) -> DNSResourceRecord {
        let typeName = try DNSName(service.fullType)
        let instanceName = try DNSName(service.fullName)
        return DNSResourceRecord(
            name: typeName,
            type: .ptr,
            ttl: configuration.ttl,
            rdata: .ptr(instanceName)
        )
    }

    private func makeServiceRecords(for service: MDNSService) throws(DNSError) -> [DNSResourceRecord] {
        var records: [DNSResourceRecord] = []
        let instanceName = try DNSName(service.fullName)

        if let host = service.host, let port = service.port {
            let target = try DNSName(host)
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

        records.append(DNSResourceRecord(
            name: instanceName,
            type: .txt,
            cacheFlush: true,
            ttl: configuration.ttl,
            rdata: .txt(Self.txtStrings(from: service.txt))
        ))

        return records
    }

    private func makeAddressRecords(for service: MDNSService) throws(DNSError) -> [DNSResourceRecord] {
        var records: [DNSResourceRecord] = []
        guard let host = service.host else { return records }
        let name = try DNSName(host)

        for address in service.addresses {
            if let v4 = address.wireIPv4 {
                records.append(DNSResourceRecord(
                    name: name,
                    type: .a,
                    cacheFlush: true,
                    ttl: configuration.ttl,
                    rdata: .a(v4)
                ))
            } else if let v6 = address.wireIPv6 {
                records.append(DNSResourceRecord(
                    name: name,
                    type: .aaaa,
                    cacheFlush: true,
                    ttl: configuration.ttl,
                    rdata: .aaaa(v6)
                ))
            }
        }

        return records
    }

    private func runPeriodicRefresh() async {
        while !Task.isCancelled && isStarted {
            do {
                try await Task.sleep(for: configuration.announcementInterval)
            } catch {
                if !Task.isCancelled {
                    logger?.debug("Periodic refresh sleep error: \(error)")
                }
                continue
            }

            for service in registeredServices.values {
                do {
                    try await announce(service: service)
                } catch {
                    logger?.debug("Periodic refresh announce error: \(error)")
                }
            }
        }
    }

    /// Renders `[String: [UInt8]]` TXT attributes into DNS TXT wire strings.
    static func txtStrings(from txt: [String: [UInt8]]) -> [String] {
        txt.keys.sorted().map { key in
            let value = txt[key] ?? []
            if value.isEmpty {
                return key
            }
            // TXT values are bytes; the DNS-SD wire form is "key=value".
            let valueString = String(decoding: value, as: UTF8.self)
            return "\(key)=\(valueString)"
        }
    }
}
