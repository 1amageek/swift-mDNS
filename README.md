# swift-mDNS

A high-performance, pure Swift implementation of Multicast DNS (mDNS) and DNS Service Discovery (DNS-SD).

## Features

- **Pure Swift** - No C dependencies, works on all Swift platforms
- **High Performance** - Zero-copy parsing, inline IP address storage, DNS name compression
- **RFC Compliant** - Implements RFC 1035 (DNS), RFC 6762 (mDNS), RFC 6763 (DNS-SD)
- **Modern Swift** - Uses Swift 6 concurrency with actors and Sendable types
- **Type Safe** - Strongly typed DNS records, questions, and messages

## Requirements

- Swift 6.2+
- macOS 15+ / iOS 18+ / tvOS 18+ / watchOS 11+ / visionOS 2+

## Installation

Add swift-mDNS to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/1amageek/swift-mDNS.git", from: "1.0.0")
]
```

Then add `mDNS` to your target dependencies:

```swift
.target(
    name: "YourTarget",
    dependencies: ["mDNS"]
)
```

## Usage

### Service Browsing

```swift
import mDNS

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
import mDNS

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

### Low-Level DNS Message Handling

```swift
import mDNS

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

### Working with DNS Names

```swift
import mDNS

// Create from string
let name = try DNSName("_http._tcp.local.")

// Use string literal
let name2: DNSName = "_printer._tcp.local."

// Case-insensitive comparison
let name3: DNSName = "_HTTP._TCP.LOCAL."
print(name == name3)  // true

// Encode to wire format
let encoded = name.encode()

// Decode from wire format
let (decoded, bytesConsumed) = try DNSName.decode(from: data, at: 0)
```

### Working with IP Addresses

```swift
import mDNS

// IPv4
let ipv4 = IPv4Address(192, 168, 1, 100)
let ipv4FromString = IPv4Address(string: "192.168.1.100")
print(ipv4.description)  // "192.168.1.100"

// IPv6
let ipv6 = IPv6Address(hi: 0xfe80_0000_0000_0000, lo: 0x0000_0000_0000_0001)
let ipv6FromString = IPv6Address(string: "fe80::1")
print(ipv6.description)  // "fe80::1"
```

## Performance

swift-mDNS is optimized for high throughput with minimal memory allocations.

### Benchmark Results

Measured on Apple Silicon (M-series):

| Operation | Throughput | Latency |
|-----------|------------|---------|
| IPv4Address creation | 202M ops/sec | 5 ns |
| IPv6Address creation | 479M ops/sec | 2 ns |
| IPv4Address equality | 113M ops/sec | 9 ns |
| IPv4Address parsing | 513K ops/sec | 1.9 μs |
| DNSName decoding | 3.2M ops/sec | 0.31 μs |
| DNSName encoding | 230K ops/sec | 4.3 μs |
| DNSName equality | 512K ops/sec | 2.0 μs |
| DNSMessage query decoding | 1.15M ops/sec | 0.87 μs |
| DNSMessage query encoding | 202K ops/sec | 5.0 μs |
| DNSMessage response decoding | 300K ops/sec | 3.3 μs |
| DNSMessage response encoding | 73K ops/sec | 13.7 μs |
| End-to-end roundtrip | 170K ops/sec | 5.9 μs |

### Optimization Techniques

- **Zero-copy parsing**: DNS messages are parsed directly from `UnsafeRawBufferPointer` without intermediate allocations
- **Zero-copy NIO integration**: Direct `ByteBuffer` encoding/decoding without `Data` conversion
- **Inline IP storage**: IPv4/IPv6 addresses use stack-allocated tuples instead of heap-allocated `Data`
- **DNS name compression**: Repeated name suffixes are compressed to 2-byte pointers (RFC 1035)
- **ContiguousArray**: Write buffer uses `ContiguousArray<UInt8>` for better cache locality
- **ASCII case-insensitive comparison**: DNS name equality uses byte-level comparison without string allocation
- **Non-copyable buffers**: `ReadBuffer` and `WriteBuffer` use `~Copyable` to prevent accidental copies

### Running Benchmarks

```bash
swift test --filter Benchmark
```

## API Reference

### Core Types

| Type | Description |
|------|-------------|
| `DNSName` | DNS domain name with label encoding and compression pointer support |
| `DNSQuestion` | DNS query with QU bit support for mDNS unicast responses |
| `DNSResourceRecord` | Resource record with cache-flush bit support |
| `DNSRecordData` | Typed RDATA (A, AAAA, PTR, SRV, TXT, HINFO, NSEC) |
| `DNSMessage` | Complete DNS message with header and all sections |
| `IPv4Address` | IPv4 address with inline storage |
| `IPv6Address` | IPv6 address with inline storage |

### High-Level Types

| Type | Description |
|------|-------------|
| `Service` | Represents a discovered or advertised DNS-SD service |
| `TXTRecord` | Key-value TXT record attributes (case-insensitive keys) |
| `ServiceBrowser` | Actor for browsing services via mDNS |
| `ServiceAdvertiser` | Actor for advertising services via mDNS |

### DNS Record Types

| Type | Value | Description |
|------|-------|-------------|
| `.a` | 1 | IPv4 address |
| `.aaaa` | 28 | IPv6 address |
| `.ptr` | 12 | Domain name pointer |
| `.srv` | 33 | Service location |
| `.txt` | 16 | Text strings |
| `.hinfo` | 13 | Host information |
| `.nsec` | 47 | Next secure record |
| `.any` | 255 | Any record type (queries only) |

## DNS-SD Service Discovery Flow

1. **PTR Query**: Query for `_service._protocol.local.` to get service instances
2. **PTR Response**: Returns `ServiceName._service._protocol.local.`
3. **SRV/TXT Query**: Query for the service instance name
4. **SRV Response**: Returns hostname and port
5. **TXT Response**: Returns service attributes
6. **A/AAAA Query**: Query for the hostname
7. **A/AAAA Response**: Returns IP addresses

## mDNS Protocol Details

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
- [RFC 2782](https://tools.ietf.org/html/rfc2782) - DNS SRV Records

## License

MIT License
