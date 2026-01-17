/// DNS-SD Service Model
///
/// Represents a discovered or advertised service per RFC 6763.

import Foundation

/// A DNS-SD service instance.
///
/// A service consists of:
/// - Service name (e.g., "My Printer")
/// - Service type (e.g., "_ipp._tcp")
/// - Domain (e.g., "local")
/// - Host and port from SRV record
/// - TXT record attributes
public struct Service: Sendable, Hashable, Identifiable {

    /// Unique identifier for this service.
    public var id: String {
        fullName
    }

    /// The service instance name (e.g., "My Printer").
    public let name: String

    /// The service type (e.g., "_ipp._tcp").
    public let type: String

    /// The domain (e.g., "local").
    public let domain: String

    /// The target hostname from SRV record.
    public var hostName: String?

    /// The port number from SRV record.
    public var port: UInt16?

    /// Priority from SRV record (lower is better).
    public var priority: UInt16

    /// Weight from SRV record for load balancing.
    public var weight: UInt16

    /// IPv4 addresses from A records.
    public var ipv4Addresses: [IPv4Address]

    /// IPv6 addresses from AAAA records.
    public var ipv6Addresses: [IPv6Address]

    /// TXT record attributes.
    public var txtRecord: TXTRecord

    /// Time-to-live for this service record.
    public var ttl: UInt32

    /// When this service was last seen/updated.
    public var lastSeen: Date

    /// The full service name (name.type.domain.).
    public var fullName: String {
        "\(name).\(type).\(domain)."
    }

    /// The service type with domain (type.domain.).
    public var fullType: String {
        "\(type).\(domain)."
    }

    public init(
        name: String,
        type: String,
        domain: String = "local",
        hostName: String? = nil,
        port: UInt16? = nil,
        priority: UInt16 = 0,
        weight: UInt16 = 0,
        ipv4Addresses: [IPv4Address] = [],
        ipv6Addresses: [IPv6Address] = [],
        txtRecord: TXTRecord = TXTRecord(),
        ttl: UInt32 = mdnsDefaultTTL,
        lastSeen: Date = Date()
    ) {
        self.name = name
        self.type = type
        self.domain = domain
        self.hostName = hostName
        self.port = port
        self.priority = priority
        self.weight = weight
        self.ipv4Addresses = ipv4Addresses
        self.ipv6Addresses = ipv6Addresses
        self.txtRecord = txtRecord
        self.ttl = ttl
        self.lastSeen = lastSeen
    }

    /// Whether this service has been fully resolved (has SRV data).
    public var isResolved: Bool {
        hostName != nil && port != nil
    }

    /// Whether this service has address records.
    public var hasAddresses: Bool {
        !ipv4Addresses.isEmpty || !ipv6Addresses.isEmpty
    }
}

// MARK: - TXT Record

/// A DNS TXT record containing key-value attributes.
///
/// Per RFC 6763 Section 6, TXT records contain zero or more strings,
/// each in the format "key=value" or just "key" for boolean attributes.
public struct TXTRecord: Sendable, Hashable {

    /// The raw key-value pairs.
    public private(set) var attributes: [String: String]

    /// Creates an empty TXT record.
    public init() {
        self.attributes = [:]
    }

    /// Creates a TXT record from key-value pairs.
    public init(_ attributes: [String: String]) {
        self.attributes = attributes
    }

    /// Creates a TXT record from DNS TXT strings.
    public init(strings: [String]) {
        var attrs: [String: String] = [:]
        for string in strings {
            if let equalIndex = string.firstIndex(of: "=") {
                let key = String(string[..<equalIndex])
                let value = String(string[string.index(after: equalIndex)...])
                attrs[key.lowercased()] = value
            } else if !string.isEmpty {
                // Boolean attribute
                attrs[string.lowercased()] = ""
            }
        }
        self.attributes = attrs
    }

    /// Gets a value for a key (case-insensitive).
    public subscript(key: String) -> String? {
        get { attributes[key.lowercased()] }
        set { attributes[key.lowercased()] = newValue }
    }

    /// Whether the TXT record contains a key.
    public func contains(_ key: String) -> Bool {
        attributes[key.lowercased()] != nil
    }

    /// Converts to DNS TXT string format.
    public func toStrings() -> [String] {
        attributes.map { key, value in
            value.isEmpty ? key : "\(key)=\(value)"
        }.sorted()
    }

    /// Whether this TXT record is empty.
    public var isEmpty: Bool {
        attributes.isEmpty
    }
}

// MARK: - Service Type

/// Common DNS-SD service types.
public enum ServiceType {
    /// HTTP web service.
    public static let http = "_http._tcp"

    /// HTTPS web service.
    public static let https = "_https._tcp"

    /// SSH service.
    public static let ssh = "_ssh._tcp"

    /// FTP service.
    public static let ftp = "_ftp._tcp"

    /// Printer (IPP).
    public static let ipp = "_ipp._tcp"

    /// AirPlay.
    public static let airplay = "_airplay._tcp"

    /// Apple File Sharing (AFP).
    public static let afp = "_afpovertcp._tcp"

    /// SMB file sharing.
    public static let smb = "_smb._tcp"

    /// SFTP service.
    public static let sftp = "_sftp-ssh._tcp"

    /// libp2p peer.
    public static let libp2p = "_p2p._udp"

    /// Returns the full service type string with domain.
    public static func fullType(_ type: String, domain: String = "local") -> String {
        "\(type).\(domain)."
    }
}
