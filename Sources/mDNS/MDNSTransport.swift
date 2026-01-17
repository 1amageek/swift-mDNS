/// mDNS Transport
///
/// Provides mDNS-specific transport functionality using NIOUDPTransport.

import Foundation
import NIOCore
import NIOUDPTransport
import Synchronization

/// Protocol for mDNS transport operations.
public protocol MDNSTransport: Sendable {
    /// Starts the transport (binds socket, joins multicast groups).
    func start() async throws

    /// Stops the transport.
    func stop() async

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
/// Uses `NIOUDPTransport` for UDP multicast communication with zero-copy
/// ByteBuffer encoding/decoding for optimal performance.
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
    private let udpTransport: NIOUDPTransport
    private let allocator: ByteBufferAllocator

    /// Stream of received DNS messages.
    public let messages: AsyncStream<ReceivedDNSMessage>
    private let messagesContinuation: AsyncStream<ReceivedDNSMessage>.Continuation

    private struct State: Sendable {
        var isStarted: Bool = false
        var receiveTask: Task<Void, Never>?
    }

    private let state: Mutex<State>

    /// Creates a new mDNS transport.
    ///
    /// - Parameter configuration: Transport configuration
    public init(configuration: MDNSTransportConfiguration = .default) {
        self.configuration = configuration
        self.allocator = ByteBufferAllocator()

        // Create UDP transport configured for multicast
        var udpConfig = UDPConfiguration.multicast(port: Int(mdnsPort))
        udpConfig.networkInterface = configuration.networkInterface
        self.udpTransport = NIOUDPTransport(configuration: udpConfig)

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

        // Start UDP transport
        try await udpTransport.start()

        // Join multicast groups
        if configuration.useIPv4 {
            try await udpTransport.joinMulticastGroup(
                mdnsIPv4Address,
                on: configuration.networkInterface
            )
        }

        if configuration.useIPv6 {
            try await udpTransport.joinMulticastGroup(
                mdnsIPv6Address,
                on: configuration.networkInterface
            )
        }

        // Start receiving messages
        startReceiving()
    }

    /// Stops the transport.
    public func stop() async {
        let task = state.withLock { state -> Task<Void, Never>? in
            state.isStarted = false
            let t = state.receiveTask
            state.receiveTask = nil
            return t
        }

        task?.cancel()

        // Leave multicast groups
        if configuration.useIPv4 {
            try? await udpTransport.leaveMulticastGroup(
                mdnsIPv4Address,
                on: configuration.networkInterface
            )
        }

        if configuration.useIPv6 {
            try? await udpTransport.leaveMulticastGroup(
                mdnsIPv6Address,
                on: configuration.networkInterface
            )
        }

        await udpTransport.stop()
        messagesContinuation.finish()
    }

    /// Sends a DNS message to the mDNS multicast groups.
    ///
    /// Uses zero-copy ByteBuffer encoding for optimal performance.
    public func send(_ message: DNSMessage) async throws {
        // Encode directly to ByteBuffer (zero-copy path)
        let buffer = message.encodeToByteBuffer(allocator: allocator)

        if configuration.useIPv4 {
            try await udpTransport.sendMulticast(
                buffer,
                to: mdnsIPv4Address,
                port: Int(mdnsPort)
            )
        }

        if configuration.useIPv6 {
            try await udpTransport.sendMulticast(
                buffer,
                to: mdnsIPv6Address,
                port: Int(mdnsPort)
            )
        }
    }

    /// Sends a DNS message to a specific address (for unicast responses).
    ///
    /// Uses zero-copy ByteBuffer encoding for optimal performance.
    public func send(_ message: DNSMessage, to address: SocketAddress) async throws {
        let buffer = message.encodeToByteBuffer(allocator: allocator)
        try await udpTransport.send(buffer, to: address)
    }

    // MARK: - Private

    private func startReceiving() {
        let task = Task { [weak self] in
            guard let self = self else { return }

            for await datagram in self.udpTransport.incomingDatagrams {
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
                    #if DEBUG
                    print("mDNS decode error: \(error)")
                    #endif
                }
            }
        }

        state.withLock { $0.receiveTask = task }
    }
}
