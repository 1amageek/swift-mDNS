/// Embedded mDNS transport (raw-POSIX multicast).
///
/// The Embedded-only `MDNSTransport` adapter. It drives the Embedded-clean
/// `POSIXMulticastDatagramTransport` from `swift-p2p-transport` for real
/// multicast I/O, mirroring what `NIODNSTransport` does on host: it binds the
/// wildcard address on the mDNS port (5353) with SO_REUSEADDR/SO_REUSEPORT, joins
/// the link-local mDNS groups (224.0.0.251 / ff02::fb) with IP_ADD_MEMBERSHIP /
/// IPV6_JOIN_GROUP, sets the multicast TTL/hops to 255 (RFC 6762 §11) with
/// loopback on (so same-host responders and browsers see each other), sends
/// `DNSMessage`s to the groups, and yields decoded inbound messages through
/// `messages`.
///
/// Embedded-clean: only `_Concurrency`, `DNSWire`, `P2PCoreTransport`, and
/// `P2PTransportPOSIX`; no Foundation, no NIO, no `any`. The throwing surface is
/// typed (`throws(MDNSError)`); the transport's `TransportError` is folded onto
/// `MDNSError` at this edge with a `bare catch { switch }` (no `as` cast).

#if hasFeature(Embedded)

import _Concurrency   // REQUIRED under Embedded for AsyncStream/async/Task
import DNSWire
import P2PCoreTransport
import P2PTransportPOSIX

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// The Embedded `MDNSTransport`: a functioning raw-POSIX multicast transport.
package final class EmbeddedMDNSTransport: MDNSTransport, Sendable {

    private let configuration: MDNSTransportConfiguration

    // Separate sockets per family, exactly like the NIO host adapter: each family
    // binds its own wildcard address and joins its own group. `nil` when the
    // family is disabled in the configuration.
    private let ipv4Transport: POSIXMulticastDatagramTransport?
    private let ipv6Transport: POSIXMulticastDatagramTransport?

    package let messages: AsyncStream<ReceivedDNSMessage>
    private let messagesContinuation: AsyncStream<ReceivedDNSMessage>.Continuation

    private struct State {
        var isStarted = false
        var ipv4ReceiveTask: Task<Void, Never>?
        var ipv6ReceiveTask: Task<Void, Never>?
    }

    private let state: FacadeLock<State>

    /// Creates the transport, binding a multicast socket for each enabled family.
    ///
    /// Binding (and thus a bind failure) happens in the `POSIXMulticastDatagramTransport`
    /// initializer; a family whose socket cannot be created is left `nil` so the
    /// other family can still operate. `start()` surfaces the all-families-down
    /// case as `transportUnavailable` rather than silently succeeding.
    package init(configuration: MDNSTransportConfiguration = .default) {
        self.configuration = configuration

        // IPv4: bind 0.0.0.0:5353.
        if configuration.useIPv4 {
            self.ipv4Transport = Self.makeTransport(bindAddress: Self.ipv4Wildcard)
        } else {
            self.ipv4Transport = nil
        }

        // IPv6: bind [::]:5353.
        if configuration.useIPv6 {
            self.ipv6Transport = Self.makeTransport(bindAddress: Self.ipv6Wildcard)
        } else {
            self.ipv6Transport = nil
        }

        self.state = FacadeLock(State())

        var continuation: AsyncStream<ReceivedDNSMessage>.Continuation!
        self.messages = AsyncStream { cont in
            continuation = cont
        }
        self.messagesContinuation = continuation
    }

    /// Builds a multicast transport for `bindAddress`, returning `nil` on a bind
    /// failure (the caller treats an all-`nil` set as a hard `start()` error). A
    /// `bare catch { switch }` keeps the Embedded path free of `any Error`.
    private static func makeTransport(
        bindAddress: SocketEndpoint
    ) -> POSIXMulticastDatagramTransport? {
        do {
            return try POSIXMulticastDatagramTransport(
                bindingTo: bindAddress,
                maximumDatagramSize: mdnsMaxMessageSize
            )
        } catch {
            switch error {
            case .closed, .messageTooLarge, .invalidEndpoint, .ioFailure:
                return nil
            }
        }
    }

    /// Starts the transport: configures multicast options, joins the groups, and
    /// spawns a receive loop per family.
    ///
    /// Fails loud with `transportUnavailable` if no family socket exists, or if a
    /// join fails (no silent degrade to a unicast socket that never receives
    /// multicast traffic).
    package func start() async throws(MDNSError) {
        let alreadyStarted = state.withLock { state -> Bool in
            if state.isStarted { return true }
            state.isStarted = true
            return false
        }
        guard !alreadyStarted else { return }

        guard ipv4Transport != nil || ipv6Transport != nil else {
            state.withLock { $0.isStarted = false }
            throw .transportUnavailable(
                "Embedded mDNS transport could not bind a multicast socket for any "
                + "enabled address family"
            )
        }

        if let ipv4Transport {
            do {
                try await Self.configureAndJoin(
                    ipv4Transport, group: Self.ipv4Group, family: AF_INET
                )
            } catch {
                state.withLock { $0.isStarted = false }
                throw Self.mapTransportError(error, context: "IPv4 multicast start")
            }
            startReceiving(from: ipv4Transport, isIPv4: true)
        }

        if let ipv6Transport {
            do {
                try await Self.configureAndJoin(
                    ipv6Transport, group: Self.ipv6Group, family: AF_INET6
                )
            } catch {
                state.withLock { $0.isStarted = false }
                throw Self.mapTransportError(error, context: "IPv6 multicast start")
            }
            startReceiving(from: ipv6Transport, isIPv4: false)
        }
    }

    /// Configures the multicast TTL/loopback and joins `group` for `family`.
    /// A single typed-throws function so the `start()` catch binds `TransportError`
    /// (not `any Error`, which the Embedded compiler rejects).
    private static func configureAndJoin(
        _ transport: POSIXMulticastDatagramTransport,
        group: SocketEndpoint,
        family: Int32
    ) async throws(TransportError) {
        try await transport.configureMulticast(
            ttl: mdnsMulticastTTL, loopback: true, family: family
        )
        try await transport.joinGroup(group)
    }

    /// Stops the transport: cancels the receive loops, closes the sockets (which
    /// terminates their `incoming` sequences), and finishes `messages`.
    package func shutdown() async throws(MDNSError) {
        let tasks = state.withLock { state -> (Task<Void, Never>?, Task<Void, Never>?) in
            state.isStarted = false
            let v4 = state.ipv4ReceiveTask
            let v6 = state.ipv6ReceiveTask
            state.ipv4ReceiveTask = nil
            state.ipv6ReceiveTask = nil
            return (v4, v6)
        }

        tasks.0?.cancel()
        tasks.1?.cancel()

        // Leaving the group is best-effort; closing the socket drops membership at
        // the kernel level anyway. Close terminates the `incoming` AsyncSequence so
        // the receive loops finish.
        if let ipv4Transport {
            do {
                try await ipv4Transport.leaveGroup(Self.ipv4Group)
            } catch {
                // Best effort: closing the socket drops membership at the kernel level.
            }
            await ipv4Transport.close()
        }
        if let ipv6Transport {
            do {
                try await ipv6Transport.leaveGroup(Self.ipv6Group)
            } catch {
                // Best effort: closing the socket drops membership at the kernel level.
            }
            await ipv6Transport.close()
        }

        messagesContinuation.finish()
    }

    /// Sends `message` to the enabled mDNS multicast groups.
    ///
    /// Succeeds if at least one family sends; throws only if every enabled family
    /// fails (matching the host NIO adapter). The encode runs once; the resulting
    /// `[UInt8]` is sent to each group via the transport's `Span<UInt8>` send.
    package func send(_ message: DNSMessage) async throws(MDNSError) {
        let bytes = message.encode()

        var sent = false
        var lastError: TransportError?

        if let ipv4Transport {
            do {
                try await Self.sendBytes(bytes, from: ipv4Transport, to: Self.ipv4Group)
                sent = true
            } catch {
                lastError = error
            }
        }

        if let ipv6Transport {
            do {
                try await Self.sendBytes(bytes, from: ipv6Transport, to: Self.ipv6Group)
                sent = true
            } catch {
                lastError = error
            }
        }

        if !sent {
            if let lastError {
                throw Self.mapTransportError(lastError, context: "multicast send")
            }
            // No family enabled at all: the caller asked to send with nothing to
            // send through. Surface it rather than silently succeeding.
            throw .transportUnavailable("Embedded mDNS transport has no enabled address family")
        }
    }

    // MARK: - Private

    /// Sends `bytes` to `group`, building the borrowed `Span` at the call boundary
    /// so the borrow never crosses the suspension.
    private static func sendBytes(
        _ bytes: [UInt8],
        from transport: POSIXMulticastDatagramTransport,
        to group: SocketEndpoint
    ) async throws(TransportError) {
        try await transport.send(bytes.span, to: group)
    }

    /// Spawns a receive loop over a family's `incoming` sequence, decoding each
    /// datagram and yielding it on `messages`. A malformed datagram is dropped
    /// (RFC 6762) without tearing down the loop.
    private func startReceiving(
        from transport: POSIXMulticastDatagramTransport,
        isIPv4: Bool
    ) {
        let continuation = messagesContinuation
        // `weak`/`unowned` are forbidden under Embedded; the loop terminates when
        // `shutdown()` closes the socket (its `incoming` finishes), so the strong
        // capture does not leak.
        let task = Task {
            for await datagram in transport.incoming {
                if Task.isCancelled { break }
                // Decode through a typed helper: a `do/catch` on the `throws(DNSError)`
                // decode directly inside this non-throwing closure would bind the
                // catch to `any Error`, which the Embedded compiler rejects. The
                // helper confines the typed catch and drops malformed datagrams
                // (RFC 6762) by returning `nil`.
                guard let message = Self.decodeMessage(datagram.payload) else {
                    continue
                }
                continuation.yield(
                    ReceivedDNSMessage(message: message, source: datagram.source)
                )
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

    /// Decodes a datagram payload into a `DNSMessage`, returning `nil` for a
    /// malformed payload. The typed `catch` here keeps `any Error` out of the
    /// non-throwing receive closure.
    private static func decodeMessage(_ payload: [UInt8]) -> DNSMessage? {
        do {
            return try DNSMessage.decode(from: payload)
        } catch {
            // `error` is `DNSError` (typed throw); drop the malformed datagram.
            return nil
        }
    }

    /// Folds a `TransportError` onto `MDNSError` with a `bare catch { switch }`
    /// shape (no `as` cast, no `any Error`), so each transport failure maps to a
    /// descriptive facade error.
    private static func mapTransportError(
        _ error: TransportError,
        context: String
    ) -> MDNSError {
        switch error {
        case .closed:
            return .networkError("\(context): transport closed")
        case .ioFailure:
            return .networkError("\(context): socket I/O failure")
        case .invalidEndpoint:
            return .networkError("\(context): invalid multicast endpoint")
        case let .messageTooLarge(size, maximum):
            return .networkError("\(context): message too large (\(size) > \(maximum))")
        }
    }

    // MARK: - mDNS multicast endpoints (typed, Embedded-clean)

    /// The mDNS multicast TTL / hop limit per RFC 6762 §11.
    private static let mdnsMulticastTTL: UInt8 = 255

    /// IPv4 wildcard bind address (0.0.0.0) on the mDNS port.
    private static let ipv4Wildcard = SocketEndpoint(v4: 0, 0, 0, 0, port: mdnsPort)

    /// IPv6 wildcard bind address (::) on the mDNS port.
    private static let ipv6Wildcard = SocketEndpoint(
        address: .v6(InlineIPv6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
        port: mdnsPort
    )

    /// IPv4 mDNS multicast group 224.0.0.251 on the mDNS port.
    private static let ipv4Group = SocketEndpoint(v4: 224, 0, 0, 251, port: mdnsPort)

    /// IPv6 mDNS multicast group ff02::fb on the mDNS port.
    private static let ipv6Group = SocketEndpoint(
        address: .v6(InlineIPv6(0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb)),
        port: mdnsPort
    )
}

#endif
