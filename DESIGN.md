# swift-mDNS Design

## Overview

A pure Swift implementation of Multicast DNS (mDNS, RFC 6762) and DNS Service
Discovery (DNS-SD, RFC 6763), following the Embedded-first 3-tier API design.

The package ships two products:

- **`MDNS`** (Tier-1 facade) — the host-facing browser / responder. Currency is
  `[UInt8]` / `MDNSService` / `P2PCore.IPAddress`. Network I/O is performed via
  NIO internally; no `Data` / `ByteBuffer` / NIO type appears on the public
  surface.
- **`DNSWire`** (Tier-3 codec) — the Foundation-free, `any`-free DNS/mDNS wire
  codec. A SEPARATE import: `import MDNS` does NOT pull it in.

> `Sources/MDNS/CONTEXT.md` is the authoritative module reference for the facade.
> This document describes the layering and design decisions; the code is the
> source of truth.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Tier-1 facade  (import MDNS)                                │
│  MDNSBrowser (actor), MDNSResponder (actor)                  │
│  MDNSService (value), MDNSError, MDNSDiscoveries            │
│  Currency: [UInt8] / MDNSService / P2PCore.IPAddress        │
├─────────────────────────────────────────────────────────────┤
│  MDNSTransport (package protocol)                           │
│  - mDNS-specific abstraction over UDP                       │
│  - the only place [UInt8] <-> ByteBuffer crosses the edge   │
├─────────────────────────────────────────────────────────────┤
│  NIODNSTransport (package implementation)                   │
│  - Wraps NIOUDPTransport from swift-nio-udp                 │
│  - Joins mDNS multicast groups (224.0.0.251, ff02::fb)      │
│  - Encodes/decodes DNSMessage at the datagram boundary      │
├─────────────────────────────────────────────────────────────┤
│  swift-nio-udp (NIOUDPTransport)                            │
│  - SwiftNIO DatagramBootstrap, multicast join/leave         │
├─────────────────────────────────────────────────────────────┤
│  Tier-3 codec  (import DNSWire)                             │
│  DNSMessage, DNSName, DNSResourceRecord, DNSRecordData,     │
│  IPv4Address, IPv6Address, DNSError, WriteBuffer            │
│  - Embedded-clean: no Foundation, no NIO, no `any`          │
└─────────────────────────────────────────────────────────────┘
```

## Package Dependencies

```
swift-mDNS
├── DNSWire  (Tier-3)
│   └── (no dependencies — Embedded-clean wire codec)
└── MDNS     (Tier-1 facade)
    ├── DNSWire
    ├── swift-nio-udp  (NIOUDPTransport)
    │   └── swift-nio  (NIOCore, NIOPosix)
    ├── swift-p2p-core (P2PCoreTransport — supplies IPAddress)
    └── swift-log      (Logging)
```

`DNSWire` carries no `swift-p2p-core` dependency, which keeps it free of the
macOS-26 `Span` platform requirement of P2PCore and lets `swift build --target
DNSWire` compile under Embedded Swift at a lower floor. The package's single
platform set adopts the shared Embedded-first baseline (macOS 26) because the
`MDNS` facade surfaces `P2PCore.IPAddress`.

## File Structure

```
Sources/DNSWire/             # Tier-3 wire codec (Embedded-clean)
├── DNSWire.swift            # Module documentation
├── DNSConstants.swift       # mDNS addresses, ports, record types
├── DNSError.swift           # Codec error type (DNSError)
├── DNSName.swift            # DNS name encoding/decoding with compression
├── DNSRecord.swift          # Resource records, IPv4Address / IPv6Address
├── DNSMessage.swift         # Complete DNS message encode/decode
├── MessageBuffer.swift      # WriteBuffer ([UInt8]-native) + byte ops
└── UTF8Validation.swift     # Strict UTF-8 decode (rejects malformed input)

Sources/MDNS/                # Tier-1 facade (host-only NIO adapter)
├── CONTEXT.md               # Authoritative module reference
├── MDNS.swift               # Module documentation
├── MDNSBrowser.swift        # Actor: browse for services
├── MDNSResponder.swift      # Actor: advertise services
├── MDNSService.swift        # Service value type ([UInt8] TXT, IPAddress)
├── MDNSDiscoveries.swift    # Typed AsyncSequence<MDNSService, MDNSError>
├── MDNSError.swift          # The single public facade error
├── TXTRecord.swift          # String-keyed TXT helper
├── ServiceType.swift        # Common DNS-SD service type constants
├── IPAddressBridge.swift    # DNSWire IPv4/IPv6 <-> P2PCore.IPAddress
└── MDNSTransport.swift      # package: NIO transport seam + [UInt8]/ByteBuffer edge
```

## Core Types

### MDNSService (Tier-1 value type)

A Foundation-free DNS-SD service instance. Addresses are `P2PCore.IPAddress`;
TXT values are raw `[UInt8]` (the Embedded-first currency — there is no
String-valued TXT API). `id` is the full service name, so consumers deduplicate
discoveries by `MDNSService.id`.

```swift
public struct MDNSService: Sendable, Hashable, Identifiable {
    public var name: String
    public var type: String
    public var domain: String
    public var host: String?
    public var port: UInt16?
    public var addresses: [IPAddress]
    public var txt: [String: [UInt8]]
    public var ttl: UInt32
    // ...

    public init(
        name: String,
        type: String,
        port: UInt16?,
        addresses: [IPAddress] = [],
        txt: [String: [UInt8]] = [:]
    )
}
```

### MDNSDiscoveries (typed discovery sequence)

The browser vends a typed `AsyncSequence<MDNSService, MDNSError>` rather than an
event enum. There is NO `.found` / `.updated` / `.removed` case: an updated or
removed service is delivered as a fresh `MDNSService` value carrying the current
state, and consumers key on `MDNSService.id` to deduplicate. A goodbye (TTL == 0)
re-emits the last-known state of the removed service.

```swift
public struct MDNSDiscoveries: AsyncSequence, Sendable {
    public typealias Element = MDNSService
    public typealias Failure = MDNSError
}
```

### MDNSBrowser (actor)

```swift
let browser = MDNSBrowser()
for try await service in try await browser.browse("_http._tcp.local.") {
    print("Found: \(service.name) at \(service.host ?? "unknown"):\(service.port ?? 0)")
}
```

- `browse(_:)` returns `MDNSDiscoveries`. Calling it more than once adds another
  service type to the same discovery stream, which is returned again.
- Sends PTR queries, processes responses, and (when `autoResolve` is on)
  issues SRV/TXT follow-up queries to resolve found instances.
- `stop()` finishes the discovery stream and shuts the transport down.

### MDNSResponder (actor)

```swift
let responder = MDNSResponder()
let service = MDNSService(name: "My Web Server", type: "_http._tcp", port: 8080)
try await responder.advertise(service)
try await responder.withdraw(service)   // sends a goodbye (TTL == 0)
```

- Answers incoming queries for registered services and announces with
  exponential backoff.
- `withdraw(_:)` / `stop()` send goodbye messages (TTL == 0).

### MDNSError

The single public, exhaustive error enum for the facade. A `DNSWire` codec
failure that reaches the facade is wrapped as `.codec(DNSError)` so a caller has
a single `catch`.

```swift
public enum MDNSError: Error, Equatable, Sendable {
    case notStarted
    case invalidService(String)
    case serviceNotFound(String)
    case transportUnavailable(String)
    case networkError(String)
    case codec(DNSError)
}
```

### MDNSTransport (package seam)

`MDNSTransport` is a `package` protocol, not public — it is the internal
injection seam used by tests and the NIO adapter. `NIODNSTransport` is the
production implementation that wraps `NIOUDPTransport`, joins the mDNS multicast
groups, and is the single place where `[UInt8]` crosses to / from NIO
`ByteBuffer`.

```swift
package protocol MDNSTransport: Sendable {
    func start() async throws
    func shutdown() async throws
    func send(_ message: DNSMessage) async throws
    var messages: AsyncStream<ReceivedDNSMessage> { get }
}
```

## TXT Records

TXT values are raw `[UInt8]` on `MDNSService` (`txt: [String: [UInt8]]`), per the
Embedded-first byte currency. On the wire, DNS-SD strings are rendered as
`key=value` (or a bare `key` for an empty value) and parsed back to bytes:

- Encode: `MDNSResponder` renders `[String: [UInt8]]` to sorted `key=value`
  strings.
- Decode: `MDNSBrowser` parses `"key=value"` / `"key"` strings into
  `[String: [UInt8]]`.

`Sources/MDNS/TXTRecord.swift` provides a string-keyed TXT helper (case-insensitive
keys) for callers that prefer a structured representation.

## Platform Support

| Platform | Support |
|----------|---------|
| macOS    | Yes (baseline macOS 26) |
| iOS      | Yes (18+) |
| tvOS     | Yes (18+) |
| watchOS  | Yes (11+) |
| visionOS | Yes (2+) |
| Linux    | Yes (host facade via NIO) |

`DNSWire` additionally builds under Embedded Swift
(`P2P_CORE_EMBEDDED=1 swift build --target DNSWire`).

## Usage Examples

### Browse for Services

```swift
import MDNS

let browser = MDNSBrowser()
// Iteration yields MDNSService and throws MDNSError. An updated/removed service
// arrives as a fresh value; deduplicate on service.id.
for try await service in try await browser.browse("_http._tcp.local.") {
    print("Found: \(service.name) at \(service.host ?? "?"):\(service.port ?? 0)")
}
```

### Advertise a Service

```swift
import MDNS

let responder = MDNSResponder()
let service = MDNSService(
    name: "My Web Server",
    type: "_http._tcp",
    port: 8080,
    txt: ["path": Array("/api".utf8)]
)
try await responder.advertise(service)

// Later...
try await responder.withdraw(service)
await responder.stop()
```

### Low-Level Wire Codec

```swift
import DNSWire

let query = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
let encoded: [UInt8] = query.encode()

let message = try DNSMessage.decode(from: receivedBytes)
for answer in message.answers {
    switch answer.rdata {
    case .ptr(let serviceName): print("PTR -> \(serviceName)")
    case .srv(let srv):         print("SRV -> \(srv.target):\(srv.port)")
    case .txt(let strings):     print("TXT -> \(strings)")
    case .a(let addr):          print("A -> \(addr)")
    case .aaaa(let addr):       print("AAAA -> \(addr)")
    default:                    break
    }
}
```

## Hardening (DNSWire)

The wire decoder rejects hostile input rather than trapping or silently
substituting defaults:

- strict bounds checks on all RDATA (including NSEC) and DNS names;
- decode-time RFC 1035 name-length enforcement;
- strict UTF-8 in TXT/HINFO labels (malformed input throws `DNSError`);
- compression-pointer loop / forward-reference detection;
- preservation of unrecognized opcode/rcode/class/record-type values as
  `.unknown(...)` cases rather than silent defaulting.

## References

- [RFC 1035](https://tools.ietf.org/html/rfc1035) — Domain Names
- [RFC 6762](https://tools.ietf.org/html/rfc6762) — Multicast DNS
- [RFC 6763](https://tools.ietf.org/html/rfc6763) — DNS-Based Service Discovery
- [RFC 2782](https://tools.ietf.org/html/rfc2782) — DNS SRV Records
