/// Embedded mDNS transport (no-multicast placeholder).
///
/// The Embedded-only `MDNSTransport` adapter. It exists so the `MDNS` facade
/// compiles end-to-end under Embedded Swift with a concrete default transport;
/// it is NOT yet a functioning mDNS transport.
///
/// ## Why this cannot do real I/O yet
///
/// mDNS is multicast: the transport must join the link-local groups
/// (224.0.0.251 / ff02::fb) with `IP_ADD_MEMBERSHIP` / `IPV6_JOIN_GROUP` and
/// send with the multicast TTL/interface socket options set. The Embedded-clean
/// datagram seam in `swift-p2p-transport` (`POSIXDatagramTransport` over
/// `POSIXDatagramSocket`) exposes only unicast `bind` / `sendto` / `recvfrom` —
/// there is no multicast group join/leave or multicast-send primitive on either
/// the `DatagramTransport` protocol or its POSIX socket. Until that primitive is
/// added, an Embedded mDNS transport cannot actually browse or advertise.
///
/// Rather than silently degrade to a unicast socket that never receives
/// multicast traffic (a silent fallback), `start()`/`send()` fail loudly with
/// ``MDNSError/transportUnavailable(_:)`` so the gap is explicit at the call
/// site. The host build is unaffected: it uses `NIODNSTransport`, which has full
/// NIO multicast support.

#if hasFeature(Embedded)

import _Concurrency   // REQUIRED under Embedded for AsyncStream/async
import DNSWire
import P2PCoreTransport

/// The Embedded `MDNSTransport` placeholder. Conforms to the seam so the facade
/// type-checks and links under Embedded, but reports the missing multicast
/// primitive instead of pretending to send/receive on the wire.
package final class EmbeddedMDNSTransport: MDNSTransport, Sendable {

    package let messages: AsyncStream<ReceivedDNSMessage>
    private let messagesContinuation: AsyncStream<ReceivedDNSMessage>.Continuation

    package init(configuration: MDNSTransportConfiguration = .default) {
        var continuation: AsyncStream<ReceivedDNSMessage>.Continuation!
        self.messages = AsyncStream { cont in
            continuation = cont
        }
        self.messagesContinuation = continuation
    }

    package func start() async throws(MDNSError) {
        throw MDNSError.transportUnavailable(
            "Embedded mDNS transport requires multicast group join/send, which the "
            + "swift-p2p-transport POSIX DatagramTransport does not yet provide"
        )
    }

    package func shutdown() async throws(MDNSError) {
        messagesContinuation.finish()
    }

    package func send(_ message: DNSMessage) async throws(MDNSError) {
        throw MDNSError.transportUnavailable(
            "Embedded mDNS transport cannot send: multicast send is unavailable in "
            + "the swift-p2p-transport POSIX DatagramTransport"
        )
    }
}

#endif
