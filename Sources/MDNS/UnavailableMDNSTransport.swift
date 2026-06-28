/// mDNS transport placeholder for platforms without a host multicast backend.
///
/// Some Swift targets, including WASI/WASM, do not expose UDP multicast sockets
/// to the module. The facade still compiles so applications can share DNS-SD
/// value types and fail explicitly instead of pulling host-only networking into
/// the module graph.

#if canImport(WASILibc) || (!hasFeature(Embedded) && !canImport(NIOUDPTransport))

import _Concurrency
import DNSWire

package final class UnavailableMDNSTransport: MDNSTransport, Sendable {
    package let messages: AsyncStream<ReceivedDNSMessage>

    private let continuation: AsyncStream<ReceivedDNSMessage>.Continuation

    package init(configuration: MDNSTransportConfiguration = .default) {
        let pair = AsyncStream.makeStream(of: ReceivedDNSMessage.self)
        self.messages = pair.stream
        self.continuation = pair.continuation
    }

    package func start() async throws(MDNSError) {
        throw Self.unavailable()
    }

    package func shutdown() async throws(MDNSError) {
        continuation.finish()
    }

    package func send(_ message: DNSMessage) async throws(MDNSError) {
        throw Self.unavailable()
    }

    private static func unavailable() -> MDNSError {
        .transportUnavailable(
            "mDNS multicast transport is unavailable on this platform"
        )
    }
}

#endif
