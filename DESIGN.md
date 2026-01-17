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
