/// The per-build default concrete `MDNSTransport`.
///
/// This is the single place that selects which transport the facade constructs by
/// default; the `#if` lives here, never in the facade logic. The facade stores the
/// transport behind the `any MDNSTransport` existential on host (so the
/// package-internal injection seam can swap in a test fake) and behind this
/// concrete type under Embedded (where `any` is unavailable).
///
///   host  (default):   DefaultMDNSTransport = NIODNSTransport     (NIO multicast)
///   Embedded (-c rel): DefaultMDNSTransport = EmbeddedMDNSTransport (placeholder)

#if !hasFeature(Embedded)
/// The host default transport: the NIO multicast adapter.
typealias DefaultMDNSTransport = NIODNSTransport
#else
/// The Embedded default transport: the multicast-less placeholder adapter.
typealias DefaultMDNSTransport = EmbeddedMDNSTransport
#endif
