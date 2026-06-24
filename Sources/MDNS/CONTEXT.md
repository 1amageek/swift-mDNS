# swift-mDNS

A pure Swift implementation of Multicast DNS (mDNS) and DNS Service Discovery (DNS-SD).

## Overview

This package ships two products following the Embedded-first 3-tier API design:

- **`MDNS`** (Tier-1 facade) — `MDNSBrowser` / `MDNSResponder` / `MDNSService` / `MDNSError`.
  Currency is `[UInt8]` / `MDNSService` / `P2PCore.IPAddress`. Network I/O is performed
  via NIO internally; no `Data` / `ByteBuffer` / NIO type appears on the public surface.
- **`DNSWire`** (Tier-3 codec) — the Foundation-free, `any`-free DNS/mDNS wire codec
  (`DNSMessage` / `DNSName` / `DNSResourceRecord` / `IPv4Address` / `IPv6Address` / `DNSError`).
  A SEPARATE import: `import MDNS` does NOT pull it in.

## Module Structure

```
Sources/DNSWire/             # Tier-3 wire codec (Embedded-clean, no Foundation/NIO/any)
├── DNSWire.swift            # Module documentation
├── DNSConstants.swift       # Protocol constants (ports, addresses, record types)
├── DNSError.swift           # Codec error type
├── DNSName.swift            # DNS name encoding/decoding with compression
├── DNSRecord.swift          # Resource records (A, AAAA, PTR, SRV, TXT, NSEC, ...)
├── DNSMessage.swift         # Complete DNS message format
├── MessageBuffer.swift      # `WriteBuffer` ([UInt8]-native) + byte ops
└── UTF8Validation.swift     # Strict UTF-8 decode (rejects malformed input)

Sources/MDNS/                # Tier-1 facade (host-only NIO adapter)
├── CONTEXT.md               # This file
├── MDNS.swift               # Module documentation
├── MDNSBrowser.swift        # Actor: browse for services
├── MDNSResponder.swift      # Actor: advertise services
├── MDNSService.swift        # Service value type ([UInt8] TXT, IPAddress)
├── MDNSDiscoveries.swift    # Typed `AsyncSequence<MDNSService, MDNSError>`
├── MDNSError.swift          # The single public facade error
├── TXTRecord.swift          # String-keyed TXT helper
├── ServiceType.swift        # Common DNS-SD service type constants
├── IPAddressBridge.swift    # DNSWire IPv4/IPv6 <-> P2PCore.IPAddress
└── MDNSTransport.swift      # package: NIO transport seam + [UInt8]/ByteBuffer edge
```

## Key Types

### Tier-3 wire codec (`import DNSWire`)

| Type | Description |
|------|-------------|
| `DNSName` | DNS domain name with label encoding and compression pointer support |
| `DNSQuestion` | DNS query with QU bit support for mDNS unicast responses |
| `DNSResourceRecord` | Resource record with cache-flush bit support |
| `DNSRecordData` | Typed RDATA (A, AAAA, PTR, SRV, TXT, HINFO, NSEC, unknown) |
| `DNSMessage` | Complete DNS message with header and all sections (`encode() -> [UInt8]`, `decode(from: [UInt8])`) |

### Tier-1 facade (`import MDNS`)

| Type | Description |
|------|-------------|
| `MDNSService` | A discovered or advertised DNS-SD service (`addresses: [IPAddress]`, `txt: [String: [UInt8]]`) |
| `MDNSBrowser` | Actor for browsing services; `browse(_:) -> some AsyncSequence<MDNSService, MDNSError>` |
| `MDNSResponder` | Actor for advertising services; `advertise(_:)` / `withdraw(_:)` / `stop()` |
| `MDNSError` | The single public facade error (`.codec(DNSError)` wraps wire failures) |
| `TXTRecord` | String-keyed TXT helper (case-insensitive keys) |

## Usage Examples

### Service Browsing

```swift
import MDNS

let browser = MDNSBrowser()
for try await service in try await browser.browse("_http._tcp.local.") {
    print("Found: \(service.name) at \(service.host ?? "unknown"):\(service.port ?? 0)")
}
```

### Service Advertising

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

// Later, to withdraw:
try await responder.withdraw(service)
```

### DNS Message Handling (Tier-3)

```swift
import DNSWire

// Create a query
let query = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
let encoded: [UInt8] = query.encode()

// Decode a response
let message = try DNSMessage.decode(from: receivedBytes)
for answer in message.answers {
    switch answer.rdata {
    case .ptr(let serviceName): print("  PTR -> \(serviceName)")
    case .srv(let srv):         print("  SRV -> \(srv.target):\(srv.port)")
    case .txt(let strings):     print("  TXT -> \(strings)")
    case .a(let addr):          print("  A -> \(addr)")
    case .aaaa(let addr):       print("  AAAA -> \(addr)")
    default:                    break
    }
}
```

## DNS-SD Service Discovery Flow

1. **PTR Query**: Query for `_service._protocol.local.` to get service instances
2. **PTR Response**: Returns `ServiceName._service._protocol.local.`
3. **SRV/TXT Query**: Query for the service instance name
4. **SRV Response**: Returns hostname and port
5. **TXT Response**: Returns service attributes
6. **A/AAAA Query**: Query for the hostname
7. **A/AAAA Response**: Returns IP addresses

## mDNS Specifics

- **Multicast Address**: 224.0.0.251 (IPv4) / ff02::fb (IPv6)
- **Port**: 5353
- **Message ID**: Always 0 for mDNS
- **Cache-Flush Bit**: High bit of class field indicates cache flush
- **QU Bit**: High bit of question class requests unicast response
- **Goodbye**: TTL=0 indicates record withdrawal

## Hardening (DNSWire)

The wire decoder rejects hostile input rather than trapping or silently substituting:
NSEC RDATA bounds, decode-time RFC 1035 name-length enforcement, strict UTF-8 in
TXT/HINFO labels, compression-pointer loop/forward-reference detection, and
preservation of unrecognized enum values as `.unknown(...)`.

## References

- [RFC 1035](https://tools.ietf.org/html/rfc1035) - Domain Names
- [RFC 6762](https://tools.ietf.org/html/rfc6762) - Multicast DNS
- [RFC 6763](https://tools.ietf.org/html/rfc6763) - DNS-Based Service Discovery
- [RFC 2782](https://tools.ietf.org/html/rfc2782) - SRV records

## Concurrency Model

- `MDNSBrowser` and `MDNSResponder` are actors for safe concurrent access
- `NIODNSTransport` uses `Mutex<T>` for thread-safe state management
- All public types are `Sendable`
