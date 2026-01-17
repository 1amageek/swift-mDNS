# swift-mDNS

A pure Swift implementation of Multicast DNS (mDNS) and DNS Service Discovery (DNS-SD).

## Overview

This library provides:
- DNS message encoding/decoding per RFC 1035
- mDNS multicast communication per RFC 6762
- DNS-SD service discovery per RFC 6763
- High-level APIs for browsing and advertising services

## Module Structure

```
Sources/mDNS/
├── CONTEXT.md              # This file
├── mDNS.swift              # Module documentation and re-exports
├── DNSConstants.swift      # Protocol constants (ports, addresses, record types)
├── DNSError.swift          # Error types
├── DNSName.swift           # DNS name encoding/decoding with compression
├── DNSRecord.swift         # Resource records (A, AAAA, PTR, SRV, TXT, etc.)
├── DNSMessage.swift        # Complete DNS message format
├── Service.swift           # High-level Service model and TXTRecord
├── ServiceBrowser.swift    # Browse for services on the network
├── ServiceAdvertiser.swift # Advertise services to the network
└── MDNSSocket.swift        # Low-level multicast UDP socket (optional)
```

## Key Types

### Low-Level DNS Types

| Type | Description |
|------|-------------|
| `DNSName` | DNS domain name with label encoding and compression pointer support |
| `DNSQuestion` | DNS query with QU bit support for mDNS unicast responses |
| `DNSResourceRecord` | Resource record with cache-flush bit support |
| `DNSRecordData` | Typed RDATA (A, AAAA, PTR, SRV, TXT, HINFO, NSEC) |
| `DNSMessage` | Complete DNS message with header and all sections |

### High-Level Service Types

| Type | Description |
|------|-------------|
| `Service` | Represents a discovered or advertised DNS-SD service |
| `TXTRecord` | Key-value TXT record attributes (case-insensitive keys) |
| `ServiceBrowser` | Actor for browsing services via mDNS |
| `ServiceAdvertiser` | Actor for advertising services via mDNS |

## Usage Examples

### Service Browsing

```swift
let browser = ServiceBrowser()
try await browser.start()

// Browse for HTTP services
try await browser.browse(for: "_http._tcp.local.")

for await event in browser.events {
    switch event {
    case .found(let service):
        print("Found: \(service.name) at \(service.hostName ?? "unknown"):\(service.port ?? 0)")
    case .updated(let service):
        print("Updated: \(service.name)")
    case .removed(let service):
        print("Removed: \(service.name)")
    case .error(let error):
        print("Error: \(error)")
    }
}
```

### Service Advertising

```swift
let advertiser = ServiceAdvertiser()
try await advertiser.start()

let service = Service(
    name: "My Web Server",
    type: "_http._tcp",
    port: 8080,
    txtRecord: TXTRecord(["path": "/api", "version": "1.0"])
)

try await advertiser.register(service)

// Later, to unregister:
try await advertiser.unregister(service)
```

### DNS Message Handling (Low-Level)

```swift
// Create a query
let query = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
let encoded = query.encode()

// Decode a response
let message = try DNSMessage.decode(from: receivedData)
for answer in message.answers {
    print("\(answer.name) \(answer.type) TTL=\(answer.ttl)")

    switch answer.rdata {
    case .ptr(let serviceName):
        print("  PTR -> \(serviceName)")
    case .srv(let srv):
        print("  SRV -> \(srv.target):\(srv.port)")
    case .txt(let strings):
        print("  TXT -> \(strings)")
    case .a(let addr):
        print("  A -> \(addr)")
    case .aaaa(let addr):
        print("  AAAA -> \(addr)")
    default:
        break
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

## References

- [RFC 1035](https://tools.ietf.org/html/rfc1035) - Domain Names - Implementation and Specification
- [RFC 6762](https://tools.ietf.org/html/rfc6762) - Multicast DNS
- [RFC 6763](https://tools.ietf.org/html/rfc6763) - DNS-Based Service Discovery
- [RFC 2782](https://tools.ietf.org/html/rfc2782) - A DNS RR for specifying the location of services (SRV)

## Concurrency Model

- `ServiceBrowser` and `ServiceAdvertiser` are actors for safe concurrent access
- `MDNSSocket` uses `Mutex<T>` for thread-safe state management
- All public types are `Sendable`
