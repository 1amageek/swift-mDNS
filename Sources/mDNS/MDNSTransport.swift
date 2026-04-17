/// mDNS Transport
///
/// Provides mDNS-specific transport functionality using NIOUDPTransport.

import Foundation
import NIOCore
import NIOUDPTransport
import os
import Synchronization

#if DEBUG
private let nioDNSTransportDebugLoggingEnabled =
    ProcessInfo.processInfo.environment["NIO_DNS_TRANSPORT_DEBUG"] == "1"
#else
private let nioDNSTransportDebugLoggingEnabled = false
#endif

private let nioDNSTransportLogger = Logger(subsystem: "mDNS", category: "Transport")

@inline(__always)
private func nioDNSDebugLog(_ message: @autoclosure () -> String) {
    guard nioDNSTransportDebugLoggingEnabled else { return }
    let text = message()
    nioDNSTransportLogger.debug("\(text, privacy: .public)")
}

/// Protocol for mDNS transport operations.
public protocol MDNSTransport: Sendable {
    /// Starts the transport (binds socket, joins multicast groups).
    func start() async throws

    /// Stops the transport.
    func shutdown() async throws

    /// Sends a DNS message to the mDNS multicast groups.
    func send(_ message: DNSMessage) async throws

    /// Stream of received DNS messages with source address.
    var messages: AsyncStream<ReceivedDNSMessage> { get }
}

/// A received DNS message with its source address.
public struct ReceivedDNSMessage: Sendable {
    /// The decoded DNS message.
    public let message: DNSMessage

    /// The source address that sent this message.
    public let source: SocketAddress

    public init(message: DNSMessage, source: SocketAddress) {
        self.message = message
        self.source = source
    }
}

/// Configuration for mDNS transport.
public struct MDNSTransportConfiguration: Sendable {
    /// Whether to use IPv4 multicast (224.0.0.251).
    public var useIPv4: Bool

    /// Whether to use IPv6 multicast (ff02::fb).
    public var useIPv6: Bool

    /// Network interface name to bind to (nil = all interfaces).
    public var networkInterface: String?

    public init(
        useIPv4: Bool = true,
        useIPv6: Bool = true,
        networkInterface: String? = nil
    ) {
        self.useIPv4 = useIPv4
        self.useIPv6 = useIPv6
        self.networkInterface = networkInterface
    }

    public static let `default` = MDNSTransportConfiguration()
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
public final class NIODNSTransport: MDNSTransport, Sendable {

    private let configuration: MDNSTransportConfiguration

    // Separate transports for IPv4 and IPv6
    private let ipv4Transport: NIOUDPTransport?
    private let ipv6Transport: NIOUDPTransport?

    private let allocator: ByteBufferAllocator

    /// Stream of received DNS messages.
    public let messages: AsyncStream<ReceivedDNSMessage>
    private let messagesContinuation: AsyncStream<ReceivedDNSMessage>.Continuation

    private struct State: Sendable {
        var isStarted: Bool = false
        var ipv4ReceiveTask: Task<Void, Never>?
        var ipv6ReceiveTask: Task<Void, Never>?
    }

    private let state: Mutex<State>

    /// Creates a new mDNS transport.
    ///
    /// - Parameter configuration: Transport configuration
    public init(configuration: MDNSTransportConfiguration = .default) {
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
    public func start() async throws {
        let alreadyStarted = state.withLock { state in
            if state.isStarted { return true }
            state.isStarted = true
            return false
        }

        guard !alreadyStarted else { return }

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
    }

    /// Stops the transport.
    public func shutdown() async throws {
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

        // Stop IPv4 transport
        if let ipv4Transport = ipv4Transport {
            try await ipv4Transport.shutdown()
        }

        // Stop IPv6 transport
        if let ipv6Transport = ipv6Transport {
            try await ipv6Transport.shutdown()
        }

        messagesContinuation.finish()
    }

    /// Sends a DNS message to the mDNS multicast groups.
    ///
    /// Sends to both IPv4 and IPv6 multicast groups. Succeeds if at least one
    /// transport sends successfully. Only throws if all enabled transports fail.
    public func send(_ message: DNSMessage) async throws {
        // Encode directly to ByteBuffer (zero-copy path)
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
            throw error
        }
    }

    /// Sends a DNS message to a specific address (for unicast responses).
    ///
    /// Uses zero-copy ByteBuffer encoding for optimal performance.
    public func send(_ message: DNSMessage, to address: SocketAddress) async throws {
        let buffer = message.encodeToByteBuffer(allocator: allocator)

        // Determine which transport to use based on address family
        switch address {
        case .v4:
            guard let ipv4Transport = ipv4Transport else {
                throw NSError(domain: "mDNS", code: -1, userInfo: [
                    NSLocalizedDescriptionKey: "IPv4 transport not available"
                ])
            }
            try await ipv4Transport.send(buffer, to: address)
        case .v6:
            guard let ipv6Transport = ipv6Transport else {
                throw NSError(domain: "mDNS", code: -1, userInfo: [
                    NSLocalizedDescriptionKey: "IPv6 transport not available"
                ])
            }
            try await ipv6Transport.send(buffer, to: address)
        case .unixDomainSocket:
            throw NSError(domain: "mDNS", code: -1, userInfo: [
                NSLocalizedDescriptionKey: "Unix domain sockets not supported for mDNS"
            ])
        }
    }

    // MARK: - Private

    private func startReceiving(from transport: NIOUDPTransport, isIPv4: Bool) {
        let task = Task { [weak self] in
            guard let self = self else { return }

            for await datagram in transport.incomingDatagrams {
                // Decode DNS message directly from ByteBuffer (zero-copy)
                do {
                    let message = try DNSMessage.decode(from: datagram.buffer)
                    let received = ReceivedDNSMessage(
                        message: message,
                        source: datagram.remoteAddress
                    )
                    self.messagesContinuation.yield(received)
                } catch {
                    // Ignore malformed messages
                    nioDNSDebugLog("mDNS decode error (\(isIPv4 ? "IPv4" : "IPv6")): \(error)")
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
