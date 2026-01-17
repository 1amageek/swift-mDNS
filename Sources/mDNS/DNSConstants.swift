/// DNS Constants
///
/// Constants for DNS and mDNS protocols per RFC 1035, RFC 6762.

import Foundation

// MARK: - mDNS Addresses

/// mDNS multicast IPv4 address: 224.0.0.251
public let mdnsIPv4Address = "224.0.0.251"

/// mDNS multicast IPv6 address: ff02::fb
public let mdnsIPv6Address = "ff02::fb"

/// mDNS port: 5353
public let mdnsPort: UInt16 = 5353

// MARK: - DNS Record Types (RFC 1035, RFC 3596)

/// DNS record types.
public enum DNSRecordType: UInt16, Sendable {
    /// IPv4 address
    case a = 1
    /// Name server
    case ns = 2
    /// Canonical name (alias)
    case cname = 5
    /// Start of authority
    case soa = 6
    /// Pointer (for reverse lookups and service discovery)
    case ptr = 12
    /// Host information
    case hinfo = 13
    /// Mail exchange
    case mx = 15
    /// Text record
    case txt = 16
    /// IPv6 address
    case aaaa = 28
    /// Service location (RFC 2782)
    case srv = 33
    /// NSEC (RFC 4034)
    case nsec = 47
    /// Any (query only)
    case any = 255
}

// MARK: - DNS Record Classes

/// DNS record classes.
public enum DNSRecordClass: UInt16, Sendable {
    /// Internet
    case `in` = 1
    /// Chaos
    case ch = 3
    /// Hesiod
    case hs = 4
    /// Any (query only)
    case any = 255
}

/// mDNS cache-flush bit (high bit of class field).
public let dnsCacheFlushBit: UInt16 = 0x8000

// MARK: - DNS Header Flags

/// DNS opcode values.
public enum DNSOpcode: UInt8, Sendable {
    /// Standard query
    case query = 0
    /// Inverse query (obsolete)
    case iquery = 1
    /// Server status request
    case status = 2
    /// Notify
    case notify = 4
    /// Update
    case update = 5
}

/// DNS response codes.
public enum DNSResponseCode: UInt8, Sendable {
    /// No error
    case noError = 0
    /// Format error
    case formatError = 1
    /// Server failure
    case serverFailure = 2
    /// Name error (NXDOMAIN)
    case nameError = 3
    /// Not implemented
    case notImplemented = 4
    /// Refused
    case refused = 5
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
