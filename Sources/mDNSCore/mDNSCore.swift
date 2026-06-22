// mDNSCore
//
// The Embedded-clean DNS/mDNS wire codec: DNS name compression, DNSMessage /
// DNSRecord encode/decode, and the NSEC / UTF-8 / name-length hardening. This
// target is Foundation-free and existential-free (`any`-free); it operates on
// `[UInt8]` / `Span` / `UnsafeRawBufferPointer` rather than Foundation `Data`
// or NIO `ByteBuffer`.
//
// The Foundation/NIO adapter (`mDNS`) `@_exported import`s this module and adds
// the `Data` / `ByteBuffer` bridges plus the advertiser / browser / transport.
//
// ## References
//
// - RFC 1035: Domain Names - Implementation and Specification
// - RFC 6762: Multicast DNS
// - RFC 6763: DNS-Based Service Discovery
// - RFC 2782: A DNS RR for specifying the location of services (SRV)
