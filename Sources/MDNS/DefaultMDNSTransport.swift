/// The per-build default concrete `MDNSTransport`.
///
/// This is the single place that selects which transport the facade constructs by
/// default; the `#if` lives here, never in the facade logic. The facade stores the
/// transport behind the `any MDNSTransport` existential on host (so the
/// package-internal injection seam can swap in a test fake) and behind this
/// concrete type under Embedded (where `any` is unavailable).
///
///   host  (NIO present): DefaultMDNSTransport = NIODNSTransport        (NIO multicast)
///   WASI / no host I/O:  DefaultMDNSTransport = UnavailableMDNSTransport
///   Embedded POSIX:      DefaultMDNSTransport = EmbeddedMDNSTransport  (raw POSIX multicast)

#if canImport(WASILibc)
/// The default transport where WASI exposes no UDP multicast socket backend.
typealias DefaultMDNSTransport = UnavailableMDNSTransport
#elseif hasFeature(Embedded)
/// The Embedded default transport: the raw-POSIX multicast adapter.
typealias DefaultMDNSTransport = EmbeddedMDNSTransport
#elseif canImport(NIOUDPTransport)
/// The host default transport: the NIO multicast adapter.
typealias DefaultMDNSTransport = NIODNSTransport
#else
/// The default transport where no host multicast socket backend is available.
typealias DefaultMDNSTransport = UnavailableMDNSTransport
#endif
