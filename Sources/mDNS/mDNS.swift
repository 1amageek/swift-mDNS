/// swift-mDNS
///
/// A pure Swift implementation of Multicast DNS (mDNS) and DNS Service Discovery (DNS-SD).
///
/// ## Overview
///
/// This library provides:
/// - DNS message encoding/decoding per RFC 1035
/// - mDNS multicast communication per RFC 6762
/// - DNS-SD service discovery per RFC 6763
/// - High-level APIs for browsing and advertising services
///
/// ## Service Browsing
///
/// ```swift
/// let browser = ServiceBrowser()
/// try await browser.start()
///
/// // Browse for HTTP services
/// try await browser.browse(for: "_http._tcp.local.")
///
/// for await event in browser.events {
///     switch event {
///     case .found(let service):
///         print("Found: \(service.name) at \(service.hostName ?? "unknown")")
///     case .removed(let service):
///         print("Removed: \(service.name)")
///     default:
///         break
///     }
/// }
/// ```
///
/// ## Service Advertising
///
/// ```swift
/// let advertiser = ServiceAdvertiser()
/// try await advertiser.start()
///
/// let service = Service(
///     name: "My Web Server",
///     type: "_http._tcp",
///     port: 8080,
///     txtRecord: TXTRecord(["path": "/api"])
/// )
///
/// try await advertiser.register(service)
/// ```
///
/// ## DNS Message Handling
///
/// For low-level DNS message handling:
///
/// ```swift
/// // Create a query
/// let query = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
/// let encoded = query.encode()
///
/// // Decode a response
/// let message = try DNSMessage.decode(from: receivedData)
/// for answer in message.answers {
///     print("\(answer.name) \(answer.type) TTL=\(answer.ttl)")
/// }
/// ```
///
/// ## References
///
/// - RFC 1035: Domain Names - Implementation and Specification
/// - RFC 6762: Multicast DNS
/// - RFC 6763: DNS-Based Service Discovery
/// - RFC 2782: A DNS RR for specifying the location of services (SRV)

// Re-export all public types
@_exported import Foundation
