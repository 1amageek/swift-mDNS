/// mDNS Transport seam (Embedded-clean)
///
/// The package-internal transport abstraction the facade drives. The contract is
/// `[UInt8]`/`DNSMessage`-native and carries no NIO / Foundation / `any` in its
/// surface, so it compiles under Embedded Swift. The host NIO multicast adapter
/// (`NIODNSTransport`), Embedded POSIX adapter, and WASI unavailable adapter live
/// in their own `#if`-gated files and conform to this protocol.

import _Concurrency   // REQUIRED under Embedded for AsyncStream/async
import DNSWire
import P2PCoreTransport

/// Protocol for mDNS transport operations.
///
/// A driver (`MDNSBrowser` / `MDNSResponder`) sends `DNSMessage`s to the mDNS
/// multicast groups and consumes inbound `DNSMessage`s through `messages`.
/// Embedded-clean: `DNSMessage` is the Foundation-free codec type, the inbound
/// stream is a concrete `AsyncStream`, there is no NIO/Foundation in the contract,
/// and the throwing requirements are TYPED (`throws(MDNSError)`). The typed throw is
/// required under Embedded Swift: an untyped `throws` on an `async` requirement
/// erases to `any Error` across the async boundary, which the Embedded compiler
/// rejects. Each adapter maps its backend errors onto `MDNSError` at its edge.
package protocol MDNSTransport: Sendable {
    /// Starts the transport (binds socket, joins multicast groups).
    func start() async throws(MDNSError)

    /// Stops the transport.
    func shutdown() async throws(MDNSError)

    /// Sends a DNS message to the mDNS multicast groups.
    func send(_ message: DNSMessage) async throws(MDNSError)

    /// Stream of received DNS messages with source address.
    var messages: AsyncStream<ReceivedDNSMessage> { get }
}

/// A received DNS message with its source endpoint.
///
/// The source is the Foundation-free `SocketEndpoint` (not NIO's `SocketAddress`)
/// so the type is Embedded-clean. It is `nil` when the backend could not resolve
/// a source endpoint for the datagram; the facade keys only on `message`.
package struct ReceivedDNSMessage: Sendable {
    /// The decoded DNS message.
    package let message: DNSMessage

    /// The source endpoint that sent this message, if the backend resolved one.
    package let source: SocketEndpoint?

    package init(message: DNSMessage, source: SocketEndpoint? = nil) {
        self.message = message
        self.source = source
    }
}

/// Configuration for mDNS transport.
package struct MDNSTransportConfiguration: Sendable {
    /// Whether to use IPv4 multicast (224.0.0.251).
    package var useIPv4: Bool

    /// Whether to use IPv6 multicast (ff02::fb).
    package var useIPv6: Bool

    /// Network interface name to bind to (nil = all interfaces).
    package var networkInterface: String?

    package init(
        useIPv4: Bool = true,
        useIPv6: Bool = true,
        networkInterface: String? = nil
    ) {
        self.useIPv4 = useIPv4
        self.useIPv6 = useIPv6
        self.networkInterface = networkInterface
    }

    package static let `default` = MDNSTransportConfiguration()
}
