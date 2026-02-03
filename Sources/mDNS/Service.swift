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
///
/// This implementation supports both DNS-SD (single value per key) and
/// libp2p extensions (multiple values per key, e.g., multiple `dnsaddr=` entries).
///
/// ## Design
///
/// - **Storage**: Raw DNS wire format (`[String]`) with index for O(1) lookup
/// - **DNS-SD API**: `subscript` returns first value only (RFC 6763 compliant)
/// - **libp2p API**: `values(forKey:)`, `appendValue(_:forKey:)` for multiple values
public struct TXTRecord: Sendable, Hashable {

    // MARK: - Storage

    /// DNS本来の形式（順序保持）
    private var rawStrings: [String]

    /// 高速アクセス用インデックス（キー → 文字列配列内のインデックス）
    private var index: [String: [Int]]

    // MARK: - Initialization

    /// Creates an empty TXT record.
    public init() {
        self.rawStrings = []
        self.index = [:]
    }

    /// Creates a TXT record from DNS TXT strings.
    public init(strings: [String]) {
        // Filter out empty strings (per RFC 6763 Section 6.1)
        self.rawStrings = strings.filter { !$0.isEmpty }
        self.index = Self.buildIndex(from: rawStrings)
    }

    /// Creates a TXT record from key-value pairs.
    public init(_ attributes: [String: String]) {
        self.rawStrings = attributes.map { key, value in
            value.isEmpty ? key : "\(key)=\(value)"
        }.sorted()
        self.index = Self.buildIndex(from: rawStrings)
    }

    // MARK: - DNS-SD Compatible API (single value)

    /// Gets or sets the first value for a key (case-insensitive).
    ///
    /// Per RFC 6763, keys SHOULD NOT appear more than once.
    /// This subscript follows that convention by returning only the first value.
    public subscript(key: String) -> String? {
        get { values(forKey: key).first }
        set {
            removeValues(forKey: key)
            if let newValue {
                appendValue(newValue, forKey: key)
            }
        }
    }

    /// Whether the TXT record contains a key (case-insensitive).
    public func contains(_ key: String) -> Bool {
        !values(forKey: key).isEmpty
    }

    // MARK: - libp2p Extended API (multiple values)

    /// Returns all values for a key (case-insensitive).
    ///
    /// Use this when you need to access multiple values for the same key
    /// (e.g., libp2p's multiple `dnsaddr=` entries).
    public func values(forKey key: String) -> [String] {
        let lowercasedKey = key.lowercased()
        guard let indices = index[lowercasedKey] else { return [] }
        return indices.compactMap { idx in
            parseValue(from: rawStrings[idx], key: lowercasedKey)
        }
    }

    /// Appends a value for a key (case-insensitive).
    ///
    /// Unlike subscript assignment (which replaces all values),
    /// this method adds a new value while preserving existing ones.
    public mutating func appendValue(_ value: String, forKey key: String) {
        let string = value.isEmpty ? key : "\(key)=\(value)"
        rawStrings.append(string)
        let newIndex = rawStrings.count - 1
        let lowercasedKey = key.lowercased()
        index[lowercasedKey, default: []].append(newIndex)
    }

    /// Sets all values for a key (case-insensitive), replacing any existing values.
    public mutating func setValues(_ values: [String], forKey key: String) {
        removeValues(forKey: key)
        for value in values {
            appendValue(value, forKey: key)
        }
    }

    /// Removes all values for a key (case-insensitive).
    public mutating func removeValues(forKey key: String) {
        let lowercasedKey = key.lowercased()
        guard let indices = index[lowercasedKey] else { return }

        // 逆順で削除（インデックスずれ防止）
        for idx in indices.sorted().reversed() {
            rawStrings.remove(at: idx)
        }

        // インデックス再構築
        index = Self.buildIndex(from: rawStrings)
    }

    // MARK: - Wire Format

    /// Converts to DNS TXT string format.
    public func toStrings() -> [String] {
        rawStrings
    }

    /// Whether this TXT record is empty.
    public var isEmpty: Bool {
        rawStrings.isEmpty
    }

    // MARK: - Helpers

    private static func buildIndex(from strings: [String]) -> [String: [Int]] {
        var index: [String: [Int]] = [:]
        for (idx, string) in strings.enumerated() {
            if let equalIndex = string.firstIndex(of: "=") {
                let key = String(string[..<equalIndex]).lowercased()
                index[key, default: []].append(idx)
            } else if !string.isEmpty {
                let key = string.lowercased()
                index[key, default: []].append(idx)
            }
        }
        return index
    }

    private func parseValue(from string: String, key: String) -> String? {
        if let equalIndex = string.firstIndex(of: "=") {
            let k = String(string[..<equalIndex]).lowercased()
            if k == key {
                return String(string[string.index(after: equalIndex)...])
            }
        } else if string.lowercased() == key {
            return ""  // Boolean attribute
        }
        return nil
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
