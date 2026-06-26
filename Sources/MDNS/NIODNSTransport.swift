/// Host-only NIO mDNS multicast transport.
///
/// The host adapter that satisfies the Embedded-clean `MDNSTransport` seam using
/// `NIOUDPTransport` for real multicast I/O. The whole file is excluded from the
/// Embedded build (`#if !hasFeature(Embedded)`): NIO, `Foundation`, and
/// `Synchronization.Mutex` are host-only. The Embedded build supplies its own
/// `MDNSTransport` adapter (`EmbeddedMDNSTransport`).

#if !hasFeature(Embedded)

import Foundation
import NIOCore
import NIOUDPTransport
import Synchronization
import DNSWire
import P2PCoreTransport

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// MARK: - Internal [UInt8] <-> ByteBuffer adapters (host-only NIO edge)

extension DNSMessage {
    /// Encodes the message to a NIO `ByteBuffer` for the multicast send path.
    ///
    /// One bulk copy at the NIO edge; `encode()` produces the `[UInt8]` payload.
    @inline(__always)
    func encodeToByteBuffer(allocator: ByteBufferAllocator) -> ByteBuffer {
        let bytes = encode()
        var buffer = allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        return buffer
    }

    /// Decodes a message from an inbound NIO `ByteBuffer`.
    ///
    /// One bulk copy at the NIO edge into `[UInt8]`, then the Foundation-free
    /// codec decodes it.
    @inline(__always)
    static func decode(fromBuffer buffer: ByteBuffer) throws(DNSError) -> DNSMessage {
        var buffer = buffer
        let bytes = buffer.readBytes(length: buffer.readableBytes) ?? []
        return try decode(from: bytes)
    }
}

// MARK: - NIO SocketAddress -> Foundation-free SocketEndpoint bridge

extension SocketEndpoint {
    /// Builds a Foundation-free `SocketEndpoint` from a NIO `SocketAddress`, or
    /// `nil` for a unix-domain socket (mDNS never uses one). The conversion reads
    /// the raw `sockaddr` so the facade currency never surfaces a NIO type.
    init?(_ nio: SocketAddress) {
        let endpoint: SocketEndpoint? = nio.withSockAddr { ptr, _ in
            switch Int32(ptr.pointee.sa_family) {
            case AF_INET:
                return ptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin -> SocketEndpoint in
                    let port = UInt16(bigEndian: sin.pointee.sin_port)
                    let raw = sin.pointee.sin_addr.s_addr  // network byte order
                    let b = withUnsafeBytes(of: raw) { Array($0) }
                    return SocketEndpoint(address: .v4(b[0], b[1], b[2], b[3]), port: port)
                }
            case AF_INET6:
                return ptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 -> SocketEndpoint in
                    let port = UInt16(bigEndian: sin6.pointee.sin6_port)
                    let octets = withUnsafeBytes(of: sin6.pointee.sin6_addr) { Array($0) }
                    return SocketEndpoint(address: .v6(InlineIPv6(
                        octets[0], octets[1], octets[2], octets[3],
                        octets[4], octets[5], octets[6], octets[7],
                        octets[8], octets[9], octets[10], octets[11],
                        octets[12], octets[13], octets[14], octets[15]
                    )), port: port)
                }
            default:
                return nil
            }
        }
        guard let endpoint else { return nil }
        self = endpoint
    }
}

#if DEBUG
private let nioDNSTransportDebugLoggingEnabled =
    ProcessInfo.processInfo.environment["NIO_DNS_TRANSPORT_DEBUG"] == "1"
#else
private let nioDNSTransportDebugLoggingEnabled = false
#endif

@inline(__always)
private func nioDNSDebugLog(_ message: @autoclosure () -> String) {
    guard nioDNSTransportDebugLoggingEnabled else { return }
    print("[mDNS] \(message())")
}

/// NIO-based mDNS transport implementation.
///
/// Uses separate `NIOUDPTransport` instances for IPv4 and IPv6 to properly
/// handle multicast group membership. Each address family requires its own
/// socket bound to the appropriate address (0.0.0.0 for IPv4, :: for IPv6).
///
/// ## Example
/// ```swift
/// let transport = NIODNSTransport(configuration: .default)
/// try await transport.start()
///
/// // Receive messages
/// Task {
///     for await received in transport.messages {
///         print("Received: \(received.message)")
///     }
/// }
///
/// // Send query
/// let query = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
/// try await transport.send(query)
/// ```
package final class NIODNSTransport: MDNSTransport, Sendable {

    private let configuration: MDNSTransportConfiguration

    // Separate transports for IPv4 and IPv6
    private let ipv4Transport: NIOUDPTransport?
    private let ipv6Transport: NIOUDPTransport?

    private let allocator: ByteBufferAllocator

    /// Stream of received DNS messages.
    package let messages: AsyncStream<ReceivedDNSMessage>
    private let messagesContinuation: AsyncStream<ReceivedDNSMessage>.Continuation

    private struct State: Sendable {
        var isStarted: Bool = false
        var ipv4ReceiveTask: Task<Void, Never>?
        var ipv6ReceiveTask: Task<Void, Never>?
    }

    private let state: Mutex<State>

    /// Count of inbound datagrams that failed to decode and were dropped.
    ///
    /// Per RFC 6762, a malformed multicast datagram is dropped silently at the
    /// protocol level. This counter provides observability so that persistent
    /// malformed traffic (a misbehaving peer, an attack) can be detected even
    /// when debug logging is disabled. A throttled, non-debug log is emitted as
    /// the counter crosses power-of-ten thresholds.
    private let decodeFailureCount: Mutex<UInt64>

    /// The total number of inbound datagrams dropped due to decode failures.
    package var droppedDecodeFailureCount: UInt64 {
        decodeFailureCount.withLock { $0 }
    }

    /// Creates a new mDNS transport.
    ///
    /// - Parameter configuration: Transport configuration
    package init(configuration: MDNSTransportConfiguration = .default) {
        self.configuration = configuration
        self.allocator = ByteBufferAllocator()

        // Create IPv4 transport if enabled
        if configuration.useIPv4 {
            let ipv4Config = UDPConfiguration(
                bindAddress: .ipv4Any(port: Int(mdnsPort)),
                reuseAddress: true,
                reusePort: true,
                networkInterface: configuration.networkInterface,
                streamBufferSize: 200
            )
            self.ipv4Transport = NIOUDPTransport(configuration: ipv4Config)
        } else {
            self.ipv4Transport = nil
        }

        // Create IPv6 transport if enabled
        if configuration.useIPv6 {
            let ipv6Config = UDPConfiguration(
                bindAddress: .ipv6Any(port: Int(mdnsPort)),
                reuseAddress: true,
                reusePort: true,
                networkInterface: configuration.networkInterface,
                streamBufferSize: 200
            )
            self.ipv6Transport = NIOUDPTransport(configuration: ipv6Config)
        } else {
            self.ipv6Transport = nil
        }

        self.state = Mutex(State())
        self.decodeFailureCount = Mutex(0)

        // Create messages stream
        var continuation: AsyncStream<ReceivedDNSMessage>.Continuation!
        self.messages = AsyncStream { cont in
            continuation = cont
        }
        self.messagesContinuation = continuation
    }

    /// Starts the transport.
    ///
    /// Binds to mDNS port 5353 and joins multicast groups.
    package func start() async throws(MDNSError) {
        let alreadyStarted = state.withLock { state in
            if state.isStarted { return true }
            state.isStarted = true
            return false
        }

        guard !alreadyStarted else { return }

        do {
            // Start IPv4 transport and join multicast group
            if let ipv4Transport = ipv4Transport {
                nioDNSDebugLog("[NIODNSTransport] Starting IPv4 transport on port \(mdnsPort)...")
                try await ipv4Transport.start()
                let v4Addr = await ipv4Transport.localAddress
                nioDNSDebugLog("[NIODNSTransport] IPv4 transport bound to \(v4Addr.map(String.init(describing:)) ?? "nil")")
                try await ipv4Transport.joinMulticastGroup(
                    mdnsIPv4Address,
                    on: configuration.networkInterface
                )
                nioDNSDebugLog("[NIODNSTransport] IPv4 joined multicast group \(mdnsIPv4Address)")
                startReceiving(from: ipv4Transport, isIPv4: true)
            }

            // Start IPv6 transport and join multicast group
            if let ipv6Transport = ipv6Transport {
                nioDNSDebugLog("[NIODNSTransport] Starting IPv6 transport on port \(mdnsPort)...")
                try await ipv6Transport.start()
                try await ipv6Transport.joinMulticastGroup(
                    mdnsIPv6Address,
                    on: configuration.networkInterface
                )
                nioDNSDebugLog("[NIODNSTransport] IPv6 joined multicast group \(mdnsIPv6Address)")
                startReceiving(from: ipv6Transport, isIPv4: false)
            }
        } catch {
            // Roll back the started flag so a retry can re-attempt the bind, then
            // surface the NIO/socket failure mapped onto the facade error type.
            state.withLock { $0.isStarted = false }
            throw MDNSError.mapping(error, context: "NIODNSTransport start failed")
        }
    }

    /// Stops the transport.
    package func shutdown() async throws(MDNSError) {
        let tasks = state.withLock { state -> (Task<Void, Never>?, Task<Void, Never>?) in
            state.isStarted = false
            let ipv4Task = state.ipv4ReceiveTask
            let ipv6Task = state.ipv6ReceiveTask
            state.ipv4ReceiveTask = nil
            state.ipv6ReceiveTask = nil
            return (ipv4Task, ipv6Task)
        }

        tasks.0?.cancel()
        tasks.1?.cancel()

        do {
            // Stop IPv4 transport
            if let ipv4Transport = ipv4Transport {
                try await ipv4Transport.shutdown()
            }

            // Stop IPv6 transport
            if let ipv6Transport = ipv6Transport {
                try await ipv6Transport.shutdown()
            }
        } catch {
            messagesContinuation.finish()
            throw MDNSError.mapping(error, context: "NIODNSTransport shutdown failed")
        }

        messagesContinuation.finish()
    }

    /// Sends a DNS message to the mDNS multicast groups.
    ///
    /// Sends to both IPv4 and IPv6 multicast groups. Succeeds if at least one
    /// transport sends successfully. Only throws if all enabled transports fail.
    package func send(_ message: DNSMessage) async throws(MDNSError) {
        // Encode to ByteBuffer with one bulk copy at the NIO edge.
        let buffer = message.encodeToByteBuffer(allocator: allocator)
        var lastError: Error?
        var sent = false

        // Send to IPv4 multicast group
        if let ipv4Transport = ipv4Transport {
            nioDNSDebugLog("[NIODNSTransport] send: IPv4 → \(mdnsIPv4Address):\(mdnsPort), \(buffer.readableBytes) bytes")
            do {
                try await ipv4Transport.sendMulticast(
                    buffer,
                    to: mdnsIPv4Address,
                    port: Int(mdnsPort)
                )
                sent = true
                nioDNSDebugLog("[NIODNSTransport] send: IPv4 OK")
            } catch {
                lastError = error
                nioDNSDebugLog("[NIODNSTransport] send: IPv4 FAILED: \(error)")
            }
        }

        // Send to IPv6 multicast group
        if let ipv6Transport = ipv6Transport {
            nioDNSDebugLog("[NIODNSTransport] send: IPv6 → \(mdnsIPv6Address):\(mdnsPort), \(buffer.readableBytes) bytes")
            do {
                try await ipv6Transport.sendMulticast(
                    buffer,
                    to: mdnsIPv6Address,
                    port: Int(mdnsPort)
                )
                sent = true
                nioDNSDebugLog("[NIODNSTransport] send: IPv6 OK")
            } catch {
                lastError = error
                nioDNSDebugLog("[NIODNSTransport] send: IPv6 FAILED: \(error)")
            }
        }

        // Only throw if no transport succeeded
        if !sent, let error = lastError {
            throw MDNSError.mapping(error, context: "NIODNSTransport send failed")
        }
    }

    /// Sends a DNS message to a specific address (for unicast responses).
    ///
    /// Uses ByteBuffer encoding with one bulk copy at the NIO edge.
    package func send(_ message: DNSMessage, to address: SocketAddress) async throws {
        let buffer = message.encodeToByteBuffer(allocator: allocator)

        // Determine which transport to use based on address family
        switch address {
        case .v4:
            guard let ipv4Transport = ipv4Transport else {
                throw DNSError.transportUnavailable("IPv4 transport not available")
            }
            try await ipv4Transport.send(buffer, to: address)
        case .v6:
            guard let ipv6Transport = ipv6Transport else {
                throw DNSError.transportUnavailable("IPv6 transport not available")
            }
            try await ipv6Transport.send(buffer, to: address)
        case .unixDomainSocket:
            throw DNSError.transportUnavailable("Unix domain sockets not supported for mDNS")
        }
    }

    // MARK: - Private

    /// Records a dropped decode failure and emits a throttled, non-debug log.
    ///
    /// The log fires only when the running total crosses a power-of-ten threshold
    /// (1, 10, 100, ...), so a flood of malformed datagrams cannot itself become a
    /// log-spam denial of service while persistent problems remain visible.
    private func recordDecodeFailure(isIPv4: Bool, error: Error) {
        let total = decodeFailureCount.withLock { count -> UInt64 in
            count += 1
            return count
        }

        nioDNSDebugLog("mDNS decode error (\(isIPv4 ? "IPv4" : "IPv6")): \(error)")

        if total.isPowerOfTen {
            let family = isIPv4 ? "IPv4" : "IPv6"
            print("[mDNS] Dropped \(total) malformed datagram(s); most recent on \(family): \(error)")
        }
    }

    private func startReceiving(from transport: NIOUDPTransport, isIPv4: Bool) {
        let task = Task { [weak self] in
            guard let self = self else { return }

            for await datagram in transport.incomingDatagrams {
                // Decode from ByteBuffer through the host-only NIO edge adapter.
                do {
                    let message = try DNSMessage.decode(fromBuffer: datagram.buffer)
                    let received = ReceivedDNSMessage(
                        message: message,
                        source: SocketEndpoint(datagram.remoteAddress)
                    )
                    self.messagesContinuation.yield(received)
                } catch {
                    // Per RFC 6762, drop this malformed multicast datagram (do not
                    // tear down the receive loop). Record it for observability so
                    // persistent malformed traffic is detectable without debug logs.
                    self.recordDecodeFailure(isIPv4: isIPv4, error: error)
                }
            }
        }

        state.withLock { state in
            if isIPv4 {
                state.ipv4ReceiveTask = task
            } else {
                state.ipv6ReceiveTask = task
            }
        }
    }
}

private extension UInt64 {
    /// Whether the value is a positive power of ten (1, 10, 100, ...).
    var isPowerOfTen: Bool {
        guard self > 0 else { return false }
        var value = self
        while value % 10 == 0 {
            value /= 10
        }
        return value == 1
    }
}

#endif
