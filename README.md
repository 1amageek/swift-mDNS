# swift-mDNS

A pure Swift implementation of Multicast DNS (mDNS, RFC 6762) and DNS Service
Discovery (DNS-SD, RFC 6763). Embedded-first: the wire codec is Foundation-free and
the byte currency is `[UInt8]` / `MDNSService` / `P2PCore.IPAddress`; no `Data` /
`ByteBuffer` / NIO type appears on the public surface.

> **Release status.** Current release: `1.3.0`.

## Features

- **Pure Swift** — no C dependencies; the `DNSWire` codec works on all Swift platforms.
- **RFC compliant** — RFC 1035 (DNS), RFC 6762 (mDNS), RFC 6763 (DNS-SD), RFC 2782 (SRV).
- **Embedded-first** — `[UInt8]` byte currency; the `DNSWire` codec has no Foundation / NIO / `any`.
- **WASM-aware** — `DNSWire` and the `MDNS` facade compile for WASI; default
  multicast I/O is unavailable there because WASI exposes no UDP multicast socket.
- **Modern concurrency** — actors and `Sendable` types; typed-throws discovery stream.
- **Hardened parsing** — wire decoding strictly bounds-checks hostile input and throws
  `DNSError` on malformed data instead of trapping; compression-pointer jumps are
  capped; the message decoder enforces a size ceiling and caps speculative reservations;
  unknown opcode / rcode / class / record-type values are preserved (`.unknown`) rather
  than silently defaulted.

## Requirements

- Swift 6.2+
- macOS 26+ / iOS 18+ / tvOS 18+ / watchOS 11+ / visionOS 2+ (the Embedded-first
  baseline; the facade surfaces `P2PCore.IPAddress`, whose package floors at macOS 26)

## Installation

Add swift-mDNS to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/1amageek/swift-mDNS.git", from: "1.3.0")
]
```

Then add the product(s) you need to your target dependencies:

```swift
.target(
    name: "YourTarget",
    dependencies: ["MDNS"]          // and/or "DNSWire" for the raw codec
)
```

## Quick Start

### Service browsing

```swift
import MDNS

let browser = MDNSBrowser()

// Iteration yields MDNSService and throws MDNSError. An updated/removed service
// arrives as a fresh value; deduplicate on service.id.
for try await service in try await browser.browse("_http._tcp.local.") {
    print("Found: \(service.name) at \(service.host ?? "unknown"):\(service.port ?? 0)")
}
```

### Service advertising

```swift
import MDNS

let responder = MDNSResponder()

let service = MDNSService(
    name: "My Web Server",
    type: "_http._tcp",
    port: 8080,
    txt: ["path": Array("/api".utf8), "version": Array("1.0".utf8)]
)

try await responder.advertise(service)

// Later, to withdraw (sends a goodbye, TTL == 0):
try await responder.withdraw(service)
await responder.stop()
```

### Low-level DNS message handling (Tier-3)

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

## Products

This package ships two products following the Embedded-first 3-tier API design.

| Product | Tier | Import | Use it for |
|---------|------|--------|-----------|
| `MDNS` | Tier-1 facade | `import MDNS` | Browse / advertise services. `[UInt8]` / `MDNSService` / `IPAddress` currency. |
| `DNSWire` | Tier-3 codec | `import DNSWire` | The Foundation-free DNS/mDNS wire codec. Not pulled in by `import MDNS`. |

## Architecture

Three layers, top to bottom:

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
│  - host: NIODNSTransport joins multicast groups             │
│  - Embedded: EmbeddedMDNSTransport uses raw POSIX multicast │
│  - WASI: UnavailableMDNSTransport fails loudly              │
├─────────────────────────────────────────────────────────────┤
│  Tier-3 codec  (import DNSWire)                             │
│  DNSMessage, DNSName, DNSResourceRecord, DNSRecordData,     │
│  IPv4Address, IPv6Address, DNSError, WriteBuffer            │
│  - Embedded-clean: no Foundation, no NIO, no `any`          │
└─────────────────────────────────────────────────────────────┘
```

- **`MDNSService`** is a Foundation-free DNS-SD service instance: `addresses` are
  `P2PCore.IPAddress`, `txt` values are raw `[UInt8]` (no String-valued TXT API).
  `id` is the full service name, so consumers deduplicate discoveries by `id`.
- **`MDNSDiscoveries`** is the named typed sequence the browser vends:
  `AsyncSequence<MDNSService, MDNSError>`. There is no `.found` / `.updated` /
  `.removed` event enum — an updated or removed service is delivered as a fresh
  value, and a goodbye (TTL == 0) re-emits the last-known state.
- **`MDNSBrowser`** sends PTR queries and, when `autoResolve` is on, issues SRV/TXT
  follow-ups to resolve found instances. Calling `browse(_:)` more than once adds
  another service type to the same discovery stream.
- **`MDNSResponder`** answers queries for registered services and announces with
  backoff; `withdraw(_:)` / `stop()` send goodbye messages (TTL == 0).
- **`MDNSTransport`** is a `package` protocol (the test / adapter injection seam);
  `NIODNSTransport` is the host production implementation, the single place where
  `[UInt8]` crosses to / from a NIO `ByteBuffer`. WASI uses
  `UnavailableMDNSTransport` so the facade compiles without NIO or host socket
  APIs; calling `browse` / `advertise` fails with `MDNSError.transportUnavailable`.

`DNSWire` carries no `swift-p2p-core` dependency, which keeps it off the macOS-26
`Span` platform requirement of P2PCore and lets `swift build --target DNSWire`
compile under Embedded Swift and WASI. The package's single platform set still
adopts the shared Embedded-first baseline (macOS 26) because the `MDNS` facade
surfaces `P2PCore.IPAddress`. See `Sources/MDNS/CONTEXT.md` for the load-bearing invariants.

## Security

The `DNSWire` decoder rejects hostile input rather than trapping or silently
substituting defaults:

- strict bounds checks on all RDATA (including NSEC) and DNS names;
- decode-time RFC 1035 name-length enforcement (255-byte cap, applied incrementally);
- compression-pointer loop / forward-reference detection (jumps capped at 128, every
  pointer must point strictly backward and within bounds);
- a hard `DNSMessage` size ceiling enforced before any attacker-controlled section
  count is read, plus capped speculative reservations (`min(count, remainingBytes /
  minEntrySize)`) against forged 0xFFFF section counts;
- strict UTF-8 in TXT/HINFO labels (malformed input throws `DNSError`);
- preservation of unrecognized opcode/rcode/class/record-type values as `.unknown(...)`.

Inbound multicast datagrams that fail to decode are dropped per RFC 6762 (the receive
loop is never torn down) but are counted (`droppedDecodeFailureCount`) and surfaced via
a throttled log, so persistent malformed traffic stays detectable.

## RFC Compliance

| RFC | Title | Coverage |
|-----|-------|----------|
| RFC 1035 | Domain Names | Message format, name encoding/decoding, compression |
| RFC 6762 | Multicast DNS | Multicast addressing/port, cache-flush bit, QU bit, goodbye (TTL 0) |
| RFC 6763 | DNS-Based Service Discovery | PTR/SRV/TXT service-discovery flow |
| RFC 2782 | DNS SRV Records | SRV target/port/priority/weight |

## Performance

The `DNSWire` codec is optimized for throughput with minimal allocations:
index-based parsing over raw byte arrays, inline (stack-allocated) IPv4/IPv6
storage, DNS name compression, a `ContiguousArray`-backed write buffer, and
`~Copyable` buffers. The host NIO adapter performs one bulk copy at the
`[UInt8]` / `ByteBuffer` boundary.

Measured on Apple Silicon (M-series):

| Operation | Throughput | Latency |
|-----------|------------|---------|
| IPv4Address creation | 202M ops/sec | 5 ns |
| IPv6Address creation | 479M ops/sec | 2 ns |
| DNSName decoding | 3.2M ops/sec | 0.31 μs |
| DNSName encoding | 230K ops/sec | 4.3 μs |
| DNSMessage query decoding | 1.15M ops/sec | 0.87 μs |
| DNSMessage query encoding | 202K ops/sec | 5.0 μs |
| DNSMessage response decoding | 300K ops/sec | 3.3 μs |
| End-to-end roundtrip | 170K ops/sec | 5.9 μs |

Run the benchmarks:

```bash
swift test --filter Benchmark
```

## Testing

The `mDNSTests` target covers both the Tier-3 codec (`DNSWire`) and the Tier-1
facade (`MDNS`). Run with a timeout to guard against hangs:

```bash
swift test
```

Compile the WASM regression gate with:

```bash
./scripts/verify-wasm.sh
```

## References

- [RFC 1035](https://tools.ietf.org/html/rfc1035) — Domain Names — Implementation and Specification
- [RFC 6762](https://tools.ietf.org/html/rfc6762) — Multicast DNS
- [RFC 6763](https://tools.ietf.org/html/rfc6763) — DNS-Based Service Discovery
- [RFC 2782](https://tools.ietf.org/html/rfc2782) — DNS SRV Records

## License

MIT License
