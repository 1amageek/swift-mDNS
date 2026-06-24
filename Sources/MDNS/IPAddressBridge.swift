/// IP address bridge
///
/// Converts between the Tier-3 `DNSWire` wire address types
/// (`IPv4Address` / `IPv6Address`) and the facade currency type
/// `P2PCore.IPAddress`. The conversion is a fixed-size copy at the edge so the
/// facade never surfaces a codec type and the codec never depends on p2p-core.

import DNSWire
import P2PCoreTransport

extension IPAddress {
    /// Builds a facade `IPAddress` from a `DNSWire` IPv4 wire address.
    @inlinable
    init(_ wire: IPv4Address) {
        self = .v4(wire.bytes.0, wire.bytes.1, wire.bytes.2, wire.bytes.3)
    }

    /// Builds a facade `IPAddress` from a `DNSWire` IPv6 wire address.
    @inlinable
    init(_ wire: IPv6Address) {
        let b = wire.rawBytes
        self = .v6(InlineIPv6(
            b[0], b[1], b[2], b[3],
            b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11],
            b[12], b[13], b[14], b[15]
        ))
    }

    /// The `DNSWire` IPv4 wire address, or `nil` if this is an IPv6 address.
    @inlinable
    var wireIPv4: IPv4Address? {
        guard case let .v4(a, b, c, d) = self else { return nil }
        return IPv4Address(a, b, c, d)
    }

    /// The `DNSWire` IPv6 wire address, or `nil` if this is an IPv4 address.
    @inlinable
    var wireIPv6: IPv6Address? {
        guard case let .v6(octets) = self else { return nil }
        let b = octets.toArray()
        var hi: UInt64 = 0
        var lo: UInt64 = 0
        for i in 0..<8 { hi = (hi << 8) | UInt64(b[i]) }
        for i in 8..<16 { lo = (lo << 8) | UInt64(b[i]) }
        return IPv6Address(hi: hi, lo: lo)
    }
}
