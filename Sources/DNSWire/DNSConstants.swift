/// DNS Constants
///
/// Constants for DNS and mDNS protocols per RFC 1035, RFC 6762.

// MARK: - mDNS Addresses

/// mDNS multicast IPv4 address: 224.0.0.251
public let mdnsIPv4Address = "224.0.0.251"

/// mDNS multicast IPv6 address: ff02::fb
public let mdnsIPv6Address = "ff02::fb"

/// mDNS port: 5353
public let mdnsPort: UInt16 = 5353

// MARK: - DNS Record Types (RFC 1035, RFC 3596)

/// DNS record types.
///
/// Conforms to `RawRepresentable` manually so that an unrecognized wire value is
/// preserved as `.unknown(UInt16)` rather than being silently coerced to a known
/// type. The synthesized raw-value backing cannot be used once an associated-value
/// case is present, so `rawValue` and `init(rawValue:)` are implemented by hand.
public enum DNSRecordType: RawRepresentable, Sendable, Hashable {
    /// IPv4 address
    case a
    /// Name server
    case ns
    /// Canonical name (alias)
    case cname
    /// Start of authority
    case soa
    /// Pointer (for reverse lookups and service discovery)
    case ptr
    /// Host information
    case hinfo
    /// Mail exchange
    case mx
    /// Text record
    case txt
    /// IPv6 address
    case aaaa
    /// Service location (RFC 2782)
    case srv
    /// NSEC (RFC 4034)
    case nsec
    /// Any (query only)
    case any
    /// An unrecognized record type, preserving its raw wire value.
    case unknown(UInt16)

    /// Creates a record type from its wire value.
    ///
    /// Never fails: an unrecognized value is preserved as `.unknown(rawValue)`.
    @inlinable
    public init(rawValue: UInt16) {
        switch rawValue {
        case 1: self = .a
        case 2: self = .ns
        case 5: self = .cname
        case 6: self = .soa
        case 12: self = .ptr
        case 13: self = .hinfo
        case 15: self = .mx
        case 16: self = .txt
        case 28: self = .aaaa
        case 33: self = .srv
        case 47: self = .nsec
        case 255: self = .any
        default: self = .unknown(rawValue)
        }
    }

    /// The wire value for this record type.
    @inlinable
    public var rawValue: UInt16 {
        switch self {
        case .a: return 1
        case .ns: return 2
        case .cname: return 5
        case .soa: return 6
        case .ptr: return 12
        case .hinfo: return 13
        case .mx: return 15
        case .txt: return 16
        case .aaaa: return 28
        case .srv: return 33
        case .nsec: return 47
        case .any: return 255
        case .unknown(let value): return value
        }
    }
}

// MARK: - DNS Record Classes

/// DNS record classes.
///
/// Conforms to `RawRepresentable` manually so that an unrecognized class value is
/// preserved as `.unknown(UInt16)` rather than being silently defaulted to `.in`.
public enum DNSRecordClass: RawRepresentable, Sendable, Hashable {
    /// Internet
    case `in`
    /// Chaos
    case ch
    /// Hesiod
    case hs
    /// Any (query only)
    case any
    /// An unrecognized class, preserving its raw wire value.
    case unknown(UInt16)

    /// Creates a record class from its wire value.
    ///
    /// Never fails: an unrecognized value is preserved as `.unknown(rawValue)`.
    @inlinable
    public init(rawValue: UInt16) {
        switch rawValue {
        case 1: self = .in
        case 3: self = .ch
        case 4: self = .hs
        case 255: self = .any
        default: self = .unknown(rawValue)
        }
    }

    /// The wire value for this record class.
    @inlinable
    public var rawValue: UInt16 {
        switch self {
        case .in: return 1
        case .ch: return 3
        case .hs: return 4
        case .any: return 255
        case .unknown(let value): return value
        }
    }
}

/// mDNS cache-flush bit (high bit of class field).
public let dnsCacheFlushBit: UInt16 = 0x8000

// MARK: - DNS Header Flags

/// DNS opcode values.
///
/// Conforms to `RawRepresentable` manually so that an unrecognized opcode is
/// preserved as `.unknown(UInt8)` rather than being silently defaulted to `.query`.
public enum DNSOpcode: RawRepresentable, Sendable, Hashable {
    /// Standard query
    case query
    /// Inverse query (obsolete)
    case iquery
    /// Server status request
    case status
    /// Notify
    case notify
    /// Update
    case update
    /// An unrecognized opcode, preserving its raw wire value.
    case unknown(UInt8)

    /// Creates an opcode from its wire value.
    ///
    /// Never fails: an unrecognized value is preserved as `.unknown(rawValue)`.
    @inlinable
    public init(rawValue: UInt8) {
        switch rawValue {
        case 0: self = .query
        case 1: self = .iquery
        case 2: self = .status
        case 4: self = .notify
        case 5: self = .update
        default: self = .unknown(rawValue)
        }
    }

    /// The wire value for this opcode.
    @inlinable
    public var rawValue: UInt8 {
        switch self {
        case .query: return 0
        case .iquery: return 1
        case .status: return 2
        case .notify: return 4
        case .update: return 5
        case .unknown(let value): return value
        }
    }
}

/// DNS response codes.
///
/// Conforms to `RawRepresentable` manually so that an unrecognized response code is
/// preserved as `.unknown(UInt8)` rather than being silently defaulted to `.noError`.
public enum DNSResponseCode: RawRepresentable, Sendable, Hashable {
    /// No error
    case noError
    /// Format error
    case formatError
    /// Server failure
    case serverFailure
    /// Name error (NXDOMAIN)
    case nameError
    /// Not implemented
    case notImplemented
    /// Refused
    case refused
    /// An unrecognized response code, preserving its raw wire value.
    case unknown(UInt8)

    /// Creates a response code from its wire value.
    ///
    /// Never fails: an unrecognized value is preserved as `.unknown(rawValue)`.
    @inlinable
    public init(rawValue: UInt8) {
        switch rawValue {
        case 0: self = .noError
        case 1: self = .formatError
        case 2: self = .serverFailure
        case 3: self = .nameError
        case 4: self = .notImplemented
        case 5: self = .refused
        default: self = .unknown(rawValue)
        }
    }

    /// The wire value for this response code.
    @inlinable
    public var rawValue: UInt8 {
        switch self {
        case .noError: return 0
        case .formatError: return 1
        case .serverFailure: return 2
        case .nameError: return 3
        case .notImplemented: return 4
        case .refused: return 5
        case .unknown(let value): return value
        }
    }
}

// MARK: - DNS-SD Constants (RFC 6763)

/// Standard DNS-SD service type suffix.
public let dnsSDServiceTypeSuffix = "._tcp.local."
public let dnsSDServiceTypeUDPSuffix = "._udp.local."

/// DNS-SD meta-query for browsing all services.
public let dnsSDServicesMetaQuery = "_services._dns-sd._udp.local."

// MARK: - libp2p mDNS Constants

/// libp2p mDNS service type.
public let libp2pServiceType = "_p2p._udp.local."

/// Default TTL for mDNS records (in seconds).
public let mdnsDefaultTTL: UInt32 = 120

/// Goodbye TTL (0 means record is being withdrawn).
public let mdnsGoodbyeTTL: UInt32 = 0

// MARK: - DNS Message Limits

/// Maximum DNS message size for UDP.
public let dnsMaxUDPMessageSize = 512

/// Maximum DNS message size for mDNS (larger due to multicast).
public let mdnsMaxMessageSize = 9000

/// Maximum DNS name length.
public let dnsMaxNameLength = 255

/// Maximum DNS label length.
public let dnsMaxLabelLength = 63

/// Smallest possible encoded question, in bytes.
///
/// A question is a name followed by a 2-byte TYPE and a 2-byte CLASS. The
/// smallest legal name is the single root label (one zero byte), giving
/// 1 + 2 + 2 = 5 bytes. Used to bound speculative reservation against the
/// attacker-controlled QDCOUNT during decode.
public let minQuestionSize = 5

/// Smallest possible encoded resource record, in bytes.
///
/// A resource record is a question's fields plus a 4-byte TTL and a 2-byte
/// RDLENGTH; the smallest legal record has a root-label name and zero-length
/// RDATA, giving 1 + 2 + 2 + 4 + 2 = 11 bytes. Used to bound speculative
/// reservation against the attacker-controlled AN/NS/AR counts during decode.
public let minResourceRecordSize = 11
