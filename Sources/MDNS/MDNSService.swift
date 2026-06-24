/// DNS-SD Service Model (Tier-1 facade value type)
///
/// Represents a discovered or advertised service per RFC 6763. Foundation-free:
/// addresses are `P2PCore.IPAddress`, TXT values are `[UInt8]`.

import DNSWire
import P2PCoreTransport

/// A DNS-SD service instance.
///
/// A service consists of:
/// - Service name (e.g. "My Printer")
/// - Service type (e.g. "_ipp._tcp")
/// - Domain (e.g. "local")
/// - Host and port from the SRV record
/// - IP addresses from A / AAAA records
/// - TXT record attributes
public struct MDNSService: Sendable, Hashable, Identifiable {

    /// Unique identifier for this service (its full name).
    public var id: String { fullName }

    /// The service instance name (e.g. "My Printer").
    public var name: String

    /// The service type (e.g. "_ipp._tcp").
    public var type: String

    /// The domain (e.g. "local").
    public var domain: String

    /// The target hostname from the SRV record.
    public var host: String?

    /// The port number from the SRV record.
    public var port: UInt16?

    /// Priority from the SRV record (lower is better).
    public var priority: UInt16

    /// Weight from the SRV record for load balancing.
    public var weight: UInt16

    /// IP addresses from A / AAAA records.
    public var addresses: [IPAddress]

    /// TXT record attributes (raw `[UInt8]` values per the Embedded-first currency).
    public var txt: [String: [UInt8]]

    /// Time-to-live for this service record, in seconds.
    public var ttl: UInt32

    /// The full service name (name.type.domain.).
    public var fullName: String {
        "\(name).\(type).\(domain)."
    }

    /// The service type with domain (type.domain.).
    public var fullType: String {
        "\(type).\(domain)."
    }

    /// The primary facade initializer (matches the design-spec signature).
    public init(
        name: String,
        type: String,
        port: UInt16?,
        addresses: [IPAddress] = [],
        txt: [String: [UInt8]] = [:]
    ) {
        self.name = name
        self.type = type
        self.domain = "local"
        self.host = nil
        self.port = port
        self.priority = 0
        self.weight = 0
        self.addresses = addresses
        self.txt = txt
        self.ttl = mdnsDefaultTTL
    }

    /// The full initializer used when reconstructing a service from the wire.
    public init(
        name: String,
        type: String,
        domain: String = "local",
        host: String? = nil,
        port: UInt16? = nil,
        priority: UInt16 = 0,
        weight: UInt16 = 0,
        addresses: [IPAddress] = [],
        txt: [String: [UInt8]] = [:],
        ttl: UInt32 = mdnsDefaultTTL
    ) {
        self.name = name
        self.type = type
        self.domain = domain
        self.host = host
        self.port = port
        self.priority = priority
        self.weight = weight
        self.addresses = addresses
        self.txt = txt
        self.ttl = ttl
    }

    /// Whether this service has been fully resolved (has SRV data).
    public var isResolved: Bool {
        host != nil && port != nil
    }

    /// Whether this service has any address records.
    public var hasAddresses: Bool {
        !addresses.isEmpty
    }

    /// The IPv4 addresses among `addresses`.
    public var ipv4Addresses: [IPAddress] {
        addresses.filter { $0.isIPv4 }
    }

    /// The IPv6 addresses among `addresses`.
    public var ipv6Addresses: [IPAddress] {
        addresses.filter { !$0.isIPv4 }
    }
}
