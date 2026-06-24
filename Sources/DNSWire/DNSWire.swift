// DNSWire
//
// The Embedded-clean DNS/mDNS wire codec (Tier-3): DNS name compression,
// DNSMessage / DNSRecord encode/decode, and the NSEC / UTF-8 / name-length
// hardening. This target is Foundation-free and existential-free (`any`-free);
// it operates on `[UInt8]` rather than Foundation `Data` or NIO `ByteBuffer`.
//
// This is a separate product from the Tier-1 `MDNS` facade: `import MDNS` does
// NOT pull `DNSWire` in. A protocol implementer that needs the raw codec asks
// for it deliberately via `import DNSWire`. The facade performs network I/O via
// NIO internally and converts at the edge; its public surface never names a
// `DNSWire` codec type.
//
// ## References
//
// - RFC 1035: Domain Names - Implementation and Specification
// - RFC 6762: Multicast DNS
// - RFC 6763: DNS-Based Service Discovery
// - RFC 2782: A DNS RR for specifying the location of services (SRV)
