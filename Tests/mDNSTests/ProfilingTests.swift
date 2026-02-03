/// ProfilingTests - Tests for profiling performance bottlenecks
///
/// Run with:
///   swift test -c release --filter ProfilingTests
///
/// Profile with Instruments:
///   1. Build: swift build -c release
///   2. Find test binary: find .build/release -name "*PackageTests"
///   3. Run with Instruments

import Testing
import Foundation
@testable import mDNS

@Suite("Profiling Tests")
struct ProfilingTests {

    // MARK: - IPv4 Address Profiling

    @Test("Profile IPv4Address string parsing - hot path")
    func profileIPv4Parsing() throws {
        let samples = [
            "192.168.1.1",
            "10.0.0.1",
            "127.0.0.1",
            "255.255.255.255",
            "8.8.8.8",
            "172.16.0.1",
            "224.0.0.251",
            "1.1.1.1"
        ]

        // Large iteration count for profiling
        let iterations = 1_000_000
        var results: [IPv4Address?] = []
        results.reserveCapacity(iterations * samples.count)

        let start = CFAbsoluteTimeGetCurrent()

        for _ in 0..<iterations {
            for sample in samples {
                results.append(IPv4Address(string: sample))
            }
        }

        let elapsed = CFAbsoluteTimeGetCurrent() - start
        let totalOps = iterations * samples.count
        let opsPerSecond = Double(totalOps) / elapsed
        let nsPerOp = (elapsed / Double(totalOps)) * 1_000_000_000

        print("IPv4 Parsing Profile:")
        print("  Total ops: \(totalOps)")
        print("  Time: \(String(format: "%.3f", elapsed))s")
        print("  Throughput: \(String(format: "%.0f", opsPerSecond)) ops/sec")
        print("  Latency: \(String(format: "%.1f", nsPerOp)) ns/op")

        // Prevent optimization
        #expect(results.count == totalOps)
    }

    @Test("Profile IPv4Address creation - constructor")
    func profileIPv4Creation() throws {
        let iterations = 10_000_000
        var results: [IPv4Address] = []
        results.reserveCapacity(iterations)

        let start = CFAbsoluteTimeGetCurrent()

        for i in 0..<iterations {
            let b = UInt8(i & 0xFF)
            results.append(IPv4Address(192, 168, 1, b))
        }

        let elapsed = CFAbsoluteTimeGetCurrent() - start
        let opsPerSecond = Double(iterations) / elapsed
        let nsPerOp = (elapsed / Double(iterations)) * 1_000_000_000

        print("IPv4 Creation Profile:")
        print("  Total ops: \(iterations)")
        print("  Time: \(String(format: "%.3f", elapsed))s")
        print("  Throughput: \(String(format: "%.0f", opsPerSecond)) ops/sec")
        print("  Latency: \(String(format: "%.1f", nsPerOp)) ns/op")

        #expect(results.count == iterations)
    }

    @Test("Profile IPv4Address equality - comparison")
    func profileIPv4Equality() throws {
        let addr1 = IPv4Address(192, 168, 1, 100)
        let addr2 = IPv4Address(192, 168, 1, 100)
        let addr3 = IPv4Address(192, 168, 1, 101)

        let iterations = 10_000_000
        var equalCount = 0

        let start = CFAbsoluteTimeGetCurrent()

        for i in 0..<iterations {
            if i % 2 == 0 {
                if addr1 == addr2 { equalCount += 1 }
            } else {
                if addr1 == addr3 { equalCount += 1 }
            }
        }

        let elapsed = CFAbsoluteTimeGetCurrent() - start
        let opsPerSecond = Double(iterations) / elapsed
        let nsPerOp = (elapsed / Double(iterations)) * 1_000_000_000

        print("IPv4 Equality Profile:")
        print("  Total ops: \(iterations)")
        print("  Time: \(String(format: "%.3f", elapsed))s")
        print("  Throughput: \(String(format: "%.0f", opsPerSecond)) ops/sec")
        print("  Latency: \(String(format: "%.1f", nsPerOp)) ns/op")

        #expect(equalCount > 0)
    }

    // MARK: - IPv6 Address Profiling

    @Test("Profile IPv6Address string parsing - hot path")
    func profileIPv6Parsing() throws {
        let samples = [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "fe80::1",
            "::1",
            "2001:db8::8a2e:370:7334",
            "ff02::fb",
            "2001:db8:0:0:1:0:0:1",
            "::ffff:192.0.2.1"  // This will fail parsing, but tests error path
        ]

        let iterations = 500_000
        var results: [IPv6Address?] = []
        results.reserveCapacity(iterations * samples.count)

        let start = CFAbsoluteTimeGetCurrent()

        for _ in 0..<iterations {
            for sample in samples {
                results.append(IPv6Address(string: sample))
            }
        }

        let elapsed = CFAbsoluteTimeGetCurrent() - start
        let totalOps = iterations * samples.count
        let opsPerSecond = Double(totalOps) / elapsed
        let nsPerOp = (elapsed / Double(totalOps)) * 1_000_000_000

        print("IPv6 Parsing Profile:")
        print("  Total ops: \(totalOps)")
        print("  Time: \(String(format: "%.3f", elapsed))s")
        print("  Throughput: \(String(format: "%.0f", opsPerSecond)) ops/sec")
        print("  Latency: \(String(format: "%.1f", nsPerOp)) ns/op")

        #expect(results.count == totalOps)
    }

    @Test("Profile IPv6Address creation - constructor")
    func profileIPv6Creation() throws {
        let iterations = 10_000_000
        var results: [IPv6Address] = []
        results.reserveCapacity(iterations)

        let start = CFAbsoluteTimeGetCurrent()

        for i in 0..<iterations {
            let lo = UInt64(i)
            results.append(IPv6Address(hi: 0xfe80_0000_0000_0000, lo: lo))
        }

        let elapsed = CFAbsoluteTimeGetCurrent() - start
        let opsPerSecond = Double(iterations) / elapsed
        let nsPerOp = (elapsed / Double(iterations)) * 1_000_000_000

        print("IPv6 Creation Profile:")
        print("  Total ops: \(iterations)")
        print("  Time: \(String(format: "%.3f", elapsed))s")
        print("  Throughput: \(String(format: "%.0f", opsPerSecond)) ops/sec")
        print("  Latency: \(String(format: "%.1f", nsPerOp)) ns/op")

        #expect(results.count == iterations)
    }

    // MARK: - DNS Message Profiling

    @Test("Profile DNS message encoding/decoding roundtrip")
    func profileDNSMessageRoundtrip() throws {
        // Create a realistic mDNS query
        let query = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")

        let iterations = 100_000
        var results: [DNSMessage] = []
        results.reserveCapacity(iterations)

        let start = CFAbsoluteTimeGetCurrent()

        for _ in 0..<iterations {
            let encoded = query.encode()
            let decoded = try DNSMessage.decode(from: encoded)
            results.append(decoded)
        }

        let elapsed = CFAbsoluteTimeGetCurrent() - start
        let opsPerSecond = Double(iterations) / elapsed
        let nsPerOp = (elapsed / Double(iterations)) * 1_000_000_000

        print("DNS Message Roundtrip Profile:")
        print("  Total ops: \(iterations)")
        print("  Time: \(String(format: "%.3f", elapsed))s")
        print("  Throughput: \(String(format: "%.0f", opsPerSecond)) ops/sec")
        print("  Latency: \(String(format: "%.1f", nsPerOp)) ns/op")

        #expect(results.count == iterations)
    }

    // MARK: - Integrated Workload

    @Test("Profile realistic mDNS workload")
    func profileRealisticWorkload() throws {
        // Simulate realistic mDNS traffic pattern
        let iterations = 10_000

        var parseCount = 0
        var encodeCount = 0
        var decodeCount = 0

        let start = CFAbsoluteTimeGetCurrent()

        for i in 0..<iterations {
            // Parse IP addresses (from network packets)
            if i % 3 == 0 {
                _ = IPv4Address(string: "192.168.1.\(i % 256)")
                _ = IPv6Address(string: "fe80::1")
                parseCount += 2
            }

            // Encode/decode DNS messages
            let query = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
            let encoded = query.encode()
            encodeCount += 1

            let decoded = try DNSMessage.decode(from: encoded)
            decodeCount += 1

            // Create addresses
            _ = IPv4Address(192, 168, 1, UInt8(i & 0xFF))
        }

        let elapsed = CFAbsoluteTimeGetCurrent() - start
        let totalOps = parseCount + encodeCount + decodeCount + iterations
        let opsPerSecond = Double(totalOps) / elapsed

        print("Realistic Workload Profile:")
        print("  Iterations: \(iterations)")
        print("  Total ops: \(totalOps)")
        print("    IP parsing: \(parseCount)")
        print("    DNS encoding: \(encodeCount)")
        print("    DNS decoding: \(decodeCount)")
        print("    IP creation: \(iterations)")
        print("  Time: \(String(format: "%.3f", elapsed))s")
        print("  Throughput: \(String(format: "%.0f", opsPerSecond)) ops/sec")

        #expect(decodeCount > 0)
    }
}
