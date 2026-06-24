/// MDNS — Tier-1 facade
///
/// A pure Swift implementation of Multicast DNS (mDNS) and DNS Service Discovery
/// (DNS-SD). `import MDNS` surfaces only the facade types:
///
/// - ``MDNSBrowser`` — browse for services
/// - ``MDNSResponder`` — advertise services
/// - ``MDNSService`` — a service value type
/// - ``MDNSError`` — the single public error type
///
/// The DNS/mDNS wire codec lives in the separate Tier-3 product `DNSWire`
/// (`import DNSWire`); it is NOT pulled in by `import MDNS`. The facade performs
/// network I/O via NIO internally and exposes only `[UInt8]` / `MDNSService` /
/// `IPAddress`.
///
/// ## Service Browsing
///
/// ```swift
/// let browser = MDNSBrowser()
/// for try await service in try await browser.browse("_http._tcp.local.") {
///     print("Found: \(service.name) at \(service.host ?? "unknown")")
/// }
/// ```
///
/// ## Service Advertising
///
/// ```swift
/// let responder = MDNSResponder()
/// let service = MDNSService(
///     name: "My Web Server",
///     type: "_http._tcp",
///     port: 8080,
///     txt: ["path": Array("/api".utf8)]
/// )
/// try await responder.advertise(service)
/// ```
///
/// ## References
///
/// - RFC 1035: Domain Names - Implementation and Specification
/// - RFC 6762: Multicast DNS
/// - RFC 6763: DNS-Based Service Discovery
/// - RFC 2782: A DNS RR for specifying the location of services (SRV)
