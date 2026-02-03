# swift-mDNS Design

## Overview

Cross-platform mDNS/DNS-SD implementation using swift-nio-udp for network transport.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  High-Level API                                             │
│  ServiceBrowser (actor), ServiceAdvertiser (actor)          │
├─────────────────────────────────────────────────────────────┤
│  MDNSTransport (protocol)                                   │
│  - mDNS-specific abstraction over UDP                       │
├─────────────────────────────────────────────────────────────┤
│  NIODNSTransport (implementation)                           │
│  - Wraps NIOUDPTransport from swift-nio-udp                 │
│  - Handles multicast group join/leave                       │
│  - Decodes DNSMessage from incoming datagrams               │
├─────────────────────────────────────────────────────────────┤
│  swift-nio-udp (NIOUDPTransport)                            │
│  - SwiftNIO DatagramBootstrap                               │
│  - MulticastCapable protocol                                │
├─────────────────────────────────────────────────────────────┤
│  DNS Protocol Layer (cross-platform)                        │
│  DNSMessage, DNSName, DNSRecord, Service, etc.             │
└─────────────────────────────────────────────────────────────┘
```

## Package Dependencies

```
swift-mDNS
├── swift-nio-udp (NIOUDPTransport)
│   └── swift-nio (NIOCore, NIOPosix)
└── swift-log (Logging)
```

## File Structure

```
Sources/mDNS/
├── DNS Protocol (cross-platform, no network dependencies)
│   ├── DNSConstants.swift    # mDNS addresses, ports, record types
│   ├── DNSError.swift        # Error types
│   ├── DNSMessage.swift      # DNS message encoding/decoding
│   ├── DNSName.swift         # DNS name format (RFC 1035)
│   ├── DNSRecord.swift       # Resource records, IPv4/IPv6Address
│   └── MessageBuffer.swift   # High-performance buffers
│
├── Transport
│   └── MDNSTransport.swift   # MDNSTransport protocol + NIODNSTransport
│
├── Service Discovery
│   ├── Service.swift         # Service model
│   ├── ServiceBrowser.swift  # Browse for services
│   └── ServiceAdvertiser.swift # Advertise services
│
└── mDNS.swift                # Module exports
```

## Core Types

### MDNSTransport Protocol

```swift
public protocol MDNSTransport: Sendable {
    func start() async throws
    func stop() async
    func send(_ message: DNSMessage) async throws
    var messages: AsyncStream<ReceivedDNSMessage> { get }
}
```

### NIODNSTransport

SwiftNIO-based implementation that:
1. Creates `NIOUDPTransport` with multicast configuration
2. Joins mDNS multicast groups (224.0.0.251, ff02::fb)
3. Decodes incoming datagrams as `DNSMessage`
4. Sends encoded messages to multicast groups

### ServiceBrowser

Actor that:
- Uses `MDNSTransport` for network communication
- Sends PTR queries for service types
- Processes DNS responses to discover services
- Emits events via `AsyncStream<ServiceBrowserEvent>`

### ServiceAdvertiser

Actor that:
- Uses `MDNSTransport` for network communication
- Responds to incoming queries for registered services
- Sends announcements with exponential backoff
- Sends goodbye messages on unregister

## Key Changes from Previous Design

| Before | After |
|--------|-------|
| `import Network` | `import NIOUDPTransport` |
| `NWConnection` / `NWListener` | `NIOUDPTransport` via `MDNSTransport` |
| `NWInterface` | `interfaceName: String?` |
| `Host.current()` | `ProcessInfo.processInfo.hostName` |
| `MDNSSocket.swift` | Deleted (replaced by `NIODNSTransport`) |

## Platform Support

| Platform | Support |
|----------|---------|
| macOS | Yes |
| iOS | Yes |
| Linux | Yes |
| tvOS | Yes |
| visionOS | Yes |

## Usage Examples

### Browse for Services

```swift
import mDNS

let browser = ServiceBrowser()
try await browser.start()
try await browser.browse(for: "_http._tcp.local.")

for await event in browser.events {
    switch event {
    case .found(let service):
        print("Found: \(service.name)")
    case .updated(let service):
        print("Updated: \(service.name) at \(service.hostName ?? "?"):\(service.port ?? 0)")
    case .removed(let service):
        print("Removed: \(service.name)")
    case .error(let error):
        print("Error: \(error)")
    }
}
```

### Advertise a Service

```swift
import mDNS

let advertiser = ServiceAdvertiser()
try await advertiser.start()

let service = Service(
    name: "My Web Server",
    type: "_http._tcp",
    port: 8080,
    txtRecord: TXTRecord(["path": "/api"])
)

try await advertiser.register(service)

// Later...
try await advertiser.unregister(service)
await advertiser.stop()
```

### Custom Transport (for testing)

```swift
class MockMDNSTransport: MDNSTransport {
    var messages: AsyncStream<ReceivedDNSMessage> { ... }
    func start() async throws { }
    func stop() async { }
    func send(_ message: DNSMessage) async throws { }
}

let browser = ServiceBrowser(transport: MockMDNSTransport())
```

## TXTRecord Design (Updated 2026-02-03)

### Overview

TXTRecord supports both DNS-SD standard (RFC 6763) and libp2p extensions for multiple values per key.

### Storage Design

```swift
public struct TXTRecord {
    /// DNS wire format (preserves order)
    private var rawStrings: [String]

    /// O(1) lookup index (key → string indices)
    private var index: [String: [Int]]
}
```

### Design Goals

1. **DNS Wire Format Preservation**: Store as `[String]` to match DNS specification
2. **O(1) Lookup**: Use index for fast key-based access
3. **DNS-SD Compatibility**: Single-value API via subscript
4. **libp2p Support**: Multi-value API for `dnsaddr=` attributes
5. **Order Preservation**: Maintain insertion order for wire format

### API Design

#### DNS-SD Standard API (Single Value)

```swift
// Get/Set first value only (RFC 6763 compliant)
txtRecord["key"] = "value"
let value = txtRecord["key"]  // First value only

// Check for key existence
if txtRecord.contains("key") { ... }
```

#### libp2p Extended API (Multiple Values)

```swift
// Get all values
let values = txtRecord.values(forKey: "dnsaddr")

// Append value (preserves existing)
txtRecord.appendValue("/ip4/127.0.0.1/tcp/4001", forKey: "dnsaddr")

// Set all values (replaces existing)
txtRecord.setValues([value1, value2], forKey: "dnsaddr")

// Remove all values for key
txtRecord.removeValues(forKey: "dnsaddr")
```

### Wire Format

```swift
// Convert to DNS strings
let strings = txtRecord.toStrings()
// → ["dnsaddr=/ip4/...", "dnsaddr=/ip6/...", "key=value"]

// Create from DNS strings
let record = TXTRecord(strings: ["key=value", "key=value2"])
record["key"]  // "value" (first only)
record.values(forKey: "key")  // ["value", "value2"]
```

### Use Case: libp2p mDNS

```swift
// Encode multiple multiaddresses
var txtRecord = TXTRecord()
txtRecord.appendValue("/ip4/192.168.1.1/tcp/4001/p2p/QmId", forKey: "dnsaddr")
txtRecord.appendValue("/ip6/fe80::1/tcp/4001/p2p/QmId", forKey: "dnsaddr")
txtRecord["agent"] = "swift-libp2p/1.0"

// Decode
let dnsaddrs = txtRecord.values(forKey: "dnsaddr")
// → ["/ip4/192.168.1.1/tcp/4001/p2p/QmId", "/ip6/fe80::1/tcp/4001/p2p/QmId"]
```

### Backward Compatibility

All existing code using `subscript` continues to work:

```swift
// Before (still works)
txtRecord["key"] = "value"
let value = txtRecord["key"]

// After (enhanced with multi-value support)
txtRecord.appendValue("value2", forKey: "key")
txtRecord["key"]  // "value" (unchanged - first value)
txtRecord.values(forKey: "key")  // ["value", "value2"]
```

### Implementation Details

#### Index Building

```swift
private static func buildIndex(from strings: [String]) -> [String: [Int]] {
    var index: [String: [Int]] = [:]
    for (idx, string) in strings.enumerated() {
        if let equalIndex = string.firstIndex(of: "=") {
            let key = String(string[..<equalIndex]).lowercased()
            index[key, default: []].append(idx)
        } else if !string.isEmpty {
            // Boolean attribute
            let key = string.lowercased()
            index[key, default: []].append(idx)
        }
    }
    return index
}
```

#### Index Rebuilding

Index is rebuilt when:
- Removing values (`removeValues(forKey:)`)
- All other operations update incrementally

### Performance Characteristics

| Operation | Complexity |
|-----------|------------|
| `values(forKey:)` | O(n) where n = number of values for key |
| `appendValue(_:forKey:)` | O(1) |
| `removeValues(forKey:)` | O(n) where n = total number of strings |
| `toStrings()` | O(1) (returns reference) |

### RFC Compliance

- **RFC 1035**: Stores TXT as `[String]` array
- **RFC 6763**: Keys SHOULD NOT appear more than once (enforced by `subscript`, relaxed for libp2p)
- **libp2p mDNS spec**: Allows multiple `dnsaddr=` entries (supported by `values`/`appendValue`)
