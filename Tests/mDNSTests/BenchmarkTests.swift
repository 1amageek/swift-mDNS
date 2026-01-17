/// Performance Benchmarks for swift-mDNS
///
/// Run with: swift test --filter Benchmark

import Testing
import Foundation
@testable import mDNS

@Suite("Performance Benchmarks")
struct BenchmarkTests {

    // MARK: - DNS Name Benchmarks

    @Test("DNSName encoding performance")
    func dnsNameEncodingPerformance() throws {
        let name: DNSName = "_http._tcp.local."
        let iterations = 10_000

        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            _ = name.encode()
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let opsPerSecond = Double(iterations) / elapsed
        print("DNSName encoding: \(Int(opsPerSecond)) ops/sec (\(elapsed * 1000 / Double(iterations)) ms/op)")
        #expect(opsPerSecond > 100_000, "Expected > 100k ops/sec")
    }

    @Test("DNSName decoding performance")
    func dnsNameDecodingPerformance() throws {
        let name: DNSName = "_http._tcp.local."
        let encoded = name.encode()
        let iterations = 10_000

        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            _ = try DNSName.decode(from: encoded, at: 0)
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let opsPerSecond = Double(iterations) / elapsed
        print("DNSName decoding: \(Int(opsPerSecond)) ops/sec (\(elapsed * 1000 / Double(iterations)) ms/op)")
        #expect(opsPerSecond > 100_000, "Expected > 100k ops/sec")
    }

    @Test("DNSName equality comparison performance")
    func dnsNameEqualityPerformance() throws {
        let name1: DNSName = "WWW.EXAMPLE.LOCAL."
        let name2: DNSName = "www.example.local."
        let iterations = 100_000

        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            _ = name1 == name2
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let opsPerSecond = Double(iterations) / elapsed
        print("DNSName equality: \(Int(opsPerSecond)) ops/sec")
        #expect(opsPerSecond > 300_000, "Expected > 300k ops/sec")
    }

    // MARK: - DNS Message Benchmarks

    @Test("DNSMessage query encoding performance")
    func dnsMessageQueryEncodingPerformance() throws {
        let message = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
        let iterations = 10_000

        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            _ = message.encode()
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let opsPerSecond = Double(iterations) / elapsed
        print("DNSMessage query encoding: \(Int(opsPerSecond)) ops/sec")
        #expect(opsPerSecond > 50_000, "Expected > 50k ops/sec")
    }

    @Test("DNSMessage query decoding performance")
    func dnsMessageQueryDecodingPerformance() throws {
        let message = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
        let encoded = message.encode()
        let iterations = 10_000

        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            _ = try DNSMessage.decode(from: encoded)
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let opsPerSecond = Double(iterations) / elapsed
        print("DNSMessage query decoding: \(Int(opsPerSecond)) ops/sec")
        #expect(opsPerSecond > 50_000, "Expected > 50k ops/sec")
    }

    @Test("DNSMessage response encoding performance")
    func dnsMessageResponseEncodingPerformance() throws {
        let name: DNSName = "My Service._http._tcp.local."
        let ptrName: DNSName = "_http._tcp.local."
        let targetName: DNSName = "myhost.local."

        let ptr = DNSResourceRecord(
            name: ptrName,
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(name)
        )

        let srv = DNSResourceRecord(
            name: name,
            type: .srv,
            ttl: 120,
            rdata: .srv(SRVRecord(priority: 0, weight: 0, port: 8080, target: targetName))
        )

        let txt = DNSResourceRecord(
            name: name,
            type: .txt,
            ttl: 4500,
            rdata: .txt(["key1=value1", "key2=value2"])
        )

        let a = DNSResourceRecord(
            name: targetName,
            type: .a,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 100))
        )

        let message = DNSMessage.response(
            answers: [ptr, srv, txt],
            additional: [a]
        )

        let iterations = 10_000

        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            _ = message.encode()
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let opsPerSecond = Double(iterations) / elapsed
        print("DNSMessage response encoding: \(Int(opsPerSecond)) ops/sec")
        #expect(opsPerSecond > 20_000, "Expected > 20k ops/sec")
    }

    @Test("DNSMessage response decoding performance")
    func dnsMessageResponseDecodingPerformance() throws {
        let name: DNSName = "My Service._http._tcp.local."
        let ptrName: DNSName = "_http._tcp.local."
        let targetName: DNSName = "myhost.local."

        let ptr = DNSResourceRecord(
            name: ptrName,
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(name)
        )

        let srv = DNSResourceRecord(
            name: name,
            type: .srv,
            ttl: 120,
            rdata: .srv(SRVRecord(priority: 0, weight: 0, port: 8080, target: targetName))
        )

        let txt = DNSResourceRecord(
            name: name,
            type: .txt,
            ttl: 4500,
            rdata: .txt(["key1=value1", "key2=value2"])
        )

        let a = DNSResourceRecord(
            name: targetName,
            type: .a,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 100))
        )

        let message = DNSMessage.response(
            answers: [ptr, srv, txt],
            additional: [a]
        )

        let encoded = message.encode()
        let iterations = 10_000

        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            _ = try DNSMessage.decode(from: encoded)
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let opsPerSecond = Double(iterations) / elapsed
        print("DNSMessage response decoding: \(Int(opsPerSecond)) ops/sec")
        #expect(opsPerSecond > 20_000, "Expected > 20k ops/sec")
    }

    // MARK: - IP Address Benchmarks

    @Test("IPv4Address creation performance")
    func ipv4CreationPerformance() throws {
        let iterations = 100_000

        let start = CFAbsoluteTimeGetCurrent()
        for i in 0..<iterations {
            let b = UInt8(i & 0xFF)
            _ = IPv4Address(192, 168, b, 1)
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let opsPerSecond = Double(iterations) / elapsed
        print("IPv4Address creation: \(Int(opsPerSecond)) ops/sec")
        #expect(opsPerSecond > 10_000_000, "Expected > 10M ops/sec")
    }

    @Test("IPv4Address string parsing performance")
    func ipv4ParsingPerformance() throws {
        let iterations = 100_000

        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            _ = IPv4Address(string: "192.168.1.100")
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let opsPerSecond = Double(iterations) / elapsed
        print("IPv4Address parsing: \(Int(opsPerSecond)) ops/sec")
        #expect(opsPerSecond > 300_000, "Expected > 300k ops/sec")
    }

    @Test("IPv4Address equality performance")
    func ipv4EqualityPerformance() throws {
        let addr1 = IPv4Address(192, 168, 1, 100)
        let addr2 = IPv4Address(192, 168, 1, 100)
        let iterations = 1_000_000

        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            _ = addr1 == addr2
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let opsPerSecond = Double(iterations) / elapsed
        print("IPv4Address equality: \(Int(opsPerSecond)) ops/sec")
        #expect(opsPerSecond > 50_000_000, "Expected > 50M ops/sec")
    }

    @Test("IPv6Address creation performance")
    func ipv6CreationPerformance() throws {
        let iterations = 100_000

        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            _ = IPv6Address(hi: 0xfe80_0000_0000_0000, lo: 0x0000_0000_0000_0001)
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let opsPerSecond = Double(iterations) / elapsed
        print("IPv6Address creation: \(Int(opsPerSecond)) ops/sec")
        #expect(opsPerSecond > 10_000_000, "Expected > 10M ops/sec")
    }

    // MARK: - Name Compression Benchmarks

    @Test("Name compression effectiveness")
    func nameCompressionEffectiveness() throws {
        let serviceName: DNSName = "My Service._http._tcp.local."
        let ptrName: DNSName = "_http._tcp.local."
        let hostName: DNSName = "myhost.local."

        // Create a response with multiple records sharing name suffixes
        let ptr = DNSResourceRecord(
            name: ptrName,
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(serviceName)
        )

        let srv = DNSResourceRecord(
            name: serviceName,
            type: .srv,
            ttl: 120,
            rdata: .srv(SRVRecord(priority: 0, weight: 0, port: 8080, target: hostName))
        )

        let txt = DNSResourceRecord(
            name: serviceName,
            type: .txt,
            ttl: 4500,
            rdata: .txt(["path=/api", "version=1.0"])
        )

        let a = DNSResourceRecord(
            name: hostName,
            type: .a,
            ttl: 120,
            rdata: .a(IPv4Address(192, 168, 1, 100))
        )

        let message = DNSMessage.response(
            answers: [ptr, srv, txt],
            additional: [a]
        )

        let encoded = message.encode()

        // With compression, repeated suffixes should be replaced with 2-byte pointers
        print("Encoded message size: \(encoded.count) bytes")
        print("Names used: \(ptrName), \(serviceName), \(hostName)")

        // The encoded size should be smaller than naive encoding
        // A typical mDNS response with compression should be < 200 bytes
        #expect(encoded.count < 200, "Expected compressed message < 200 bytes, got \(encoded.count)")
    }

    // MARK: - Throughput Benchmarks

    @Test("End-to-end encode/decode throughput")
    func endToEndThroughput() throws {
        let message = try DNSMessage.mdnsQuery(for: "_http._tcp.local.")
        let iterations = 10_000

        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            let encoded = message.encode()
            _ = try DNSMessage.decode(from: encoded)
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let roundtripsPerSecond = Double(iterations) / elapsed
        print("End-to-end roundtrips: \(Int(roundtripsPerSecond)) ops/sec")
        #expect(roundtripsPerSecond > 25_000, "Expected > 25k roundtrips/sec")
    }

    @Test("Buffer reuse encoding performance")
    func bufferReusePerformance() throws {
        let name: DNSName = "_http._tcp.local."
        let question = DNSQuestion(name: name, type: .ptr)
        let message = DNSMessage.query(id: 0, questions: [question])
        let iterations = 10_000

        // Test with buffer-based encoding (buffer created fresh each time)
        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            var buffer = WriteBuffer(capacity: 512)
            message.encode(to: &buffer)
            _ = buffer.toData()
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start

        let opsPerSecond = Double(iterations) / elapsed
        print("Buffer-based encoding: \(Int(opsPerSecond)) ops/sec")
        #expect(opsPerSecond > 50_000, "Expected > 50k ops/sec")
    }
}
